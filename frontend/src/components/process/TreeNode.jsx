import React, { memo } from 'react';
import { FiXCircle, FiLayers, FiAlertTriangle, FiLock } from 'react-icons/fi';

const SEVERITY_COLORS = {
  critical: { bg: 'var(--critical-dim)', color: 'var(--critical)', border: 'var(--critical)' },
  high:     { bg: 'var(--error-dim)',    color: 'var(--error)',    border: 'var(--error)' },
  medium:   { bg: 'var(--warning-dim)',  color: 'var(--warning)',  border: 'var(--warning)' },
  low:      { bg: 'var(--success-dim)',  color: 'var(--success)',  border: 'var(--success)' },
};

function getSeverity(proc) {
  if (proc.is_suspicious) return 'high';
  const score = proc.risk_score || proc.score || 0;
  if (score >= 85) return 'critical';
  if (score >= 70) return 'high';
  if (score >= 50) return 'medium';
  return 'low';
}

// PPL (Protected Process Light) — Windows will refuse termination
const PPL_REGEX = /csrss\.exe|wininit\.exe|winlogon\.exe|services\.exe|smss\.exe|lsass\.exe|^System$|^\[?System/i;

function TreeNodeInner({
  node,
  level = 0,
  expandedPids,
  onToggle,
  onKillPid,
  onKillTree,
  killing,
  allowKillAll = false,
}) {
  if (!node) return null;

  const hasChildren = Array.isArray(node.children) && node.children.length > 0;
  const isExpanded = expandedPids ? expandedPids.has(node.pid) : false;
  const indent = level * 18;

  const isUserProcess = /explorer\.exe|notepad\.exe|msedge\.exe|chrome\.exe|firefox\.exe|Code\.exe|code\.exe/i.test(node.name || '');
  const isSystemProcess = /svchost\.exe|csrss\.exe|wininit\.exe|winlogon\.exe|services\.exe|smss\.exe|lsass\.exe|System|\[System/i.test(node.name || '');
  const isProtected = PPL_REGEX.test(node.name || '');

  const isFlagged = node.is_suspicious || isUserProcess;
  // Kill buttons: hidden for PPL. Shown for flagged/user always. Shown for others ONLY in "All" tab (allowKillAll).
  const showActions = !isProtected && (isFlagged || allowKillAll);

  // Visual identity
  let nameColor = 'var(--text-primary)';
  let nameWeight = '600';
  let rowBg = 'transparent';
  let rowBorder = 'transparent';
  let icon = '·';
  let iconColor = 'var(--text-tertiary)';

  if (node.is_suspicious) {
    nameColor = 'var(--error)';
    nameWeight = '700';
    rowBg = 'rgba(239, 68, 68, 0.06)';
    rowBorder = 'rgba(239, 68, 68, 0.35)';
    icon = '⚠';
    iconColor = 'var(--error)';
  } else if (isUserProcess) {
    nameColor = 'var(--primary)';
    nameWeight = '600';
    rowBg = 'rgba(79, 172, 254, 0.06)';
    rowBorder = 'rgba(79, 172, 254, 0.25)';
    icon = '◉';
    iconColor = 'var(--primary)';
  } else if (isSystemProcess) {
    nameColor = 'var(--text-secondary)';
    nameWeight = '500';
    icon = '◆';
    iconColor = 'var(--text-tertiary)';
  }

  return (
    <div style={{ marginLeft: indent }}>
      {/* ===== Row ===== */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          padding: '0.4rem 0.6rem',
          borderRadius: 'var(--radius-sm)',
          background: rowBg,
          border: `1px solid ${rowBorder}`,
          marginBottom: '2px',
          transition: 'all 0.15s ease',
          cursor: hasChildren ? 'pointer' : 'default',
          position: 'relative',
        }}
        onMouseEnter={(e) => {
          if (!rowBg || rowBg === 'transparent') e.currentTarget.style.background = 'var(--bg-tertiary)';
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.background = rowBg;
        }}
        onClick={() => hasChildren && onToggle && onToggle(node.pid)}
      >
        {/* Expand icon */}
        <span style={{
          width: '14px', display: 'inline-flex', alignItems: 'center',
          justifyContent: 'center', color: iconColor,
          fontSize: '10px', fontWeight: 700, flexShrink: 0,
        }}>
          {hasChildren ? (isExpanded ? '▼' : '▶') : '·'}
        </span>

        {/* Process icon */}
        <span style={{ color: iconColor, fontSize: '11px', flexShrink: 0, fontWeight: 700 }}>
          {icon}
        </span>

        {/* Process name */}
        <span style={{
          fontFamily: 'var(--font-mono)', fontSize: '0.8rem',
          fontWeight: nameWeight, color: nameColor, flexShrink: 0,
        }}>
          {node.name || 'unknown'}
        </span>

        {/* PID badge */}
        <span style={{
          fontFamily: 'var(--font-mono)', fontSize: '0.7rem',
          padding: '0.1rem 0.4rem', background: 'var(--mono-bg)',
          color: 'var(--mono-text)', border: '1px solid var(--mono-border)',
          borderRadius: 'var(--radius-sm)', flexShrink: 0,
        }}>
          PID {node.pid}
        </span>

        {/* PPID */}
        {node.parent_pid !== null && node.parent_pid !== undefined && (
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.68rem', color: 'var(--text-tertiary)', flexShrink: 0 }}>
            PPID {node.parent_pid}
          </span>
        )}

        {/* Suspicious badge */}
        {node.is_suspicious && (
          <span style={{
            display: 'inline-flex', alignItems: 'center', gap: '0.2rem',
            padding: '0.1rem 0.45rem', fontSize: '0.65rem', fontWeight: 700,
            background: 'var(--error-dim)', color: 'var(--error)',
            border: '1px solid var(--error)', borderRadius: 'var(--radius-full)',
            textTransform: 'uppercase', letterSpacing: '0.03em',
            flexShrink: 0, boxShadow: '0 0 8px var(--error-glow)',
          }}>
            <FiAlertTriangle size={9} /> Suspicious
          </span>
        )}

        {/* PPL badge */}
        {isProtected && (
          <span
            title="Protected Process Light (PPL) — Windows refuses termination"
            style={{
              display: 'inline-flex', alignItems: 'center', gap: '0.2rem',
              padding: '0.1rem 0.45rem', fontSize: '0.62rem', fontWeight: 700,
              background: 'var(--bg-tertiary)', color: 'var(--text-tertiary)',
              border: '1px solid var(--border-primary)', borderRadius: 'var(--radius-full)',
              textTransform: 'uppercase', letterSpacing: '0.03em', flexShrink: 0,
            }}
          >
            <FiLock size={9} /> PPL
          </span>
        )}

        {/* Cmdline */}
        {node.exe && (
          <span
            title={node.exe}
            style={{
              fontFamily: 'var(--font-mono)', fontSize: '0.7rem',
              color: 'var(--text-tertiary)', marginLeft: 'auto',
              maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis',
              whiteSpace: 'nowrap', flexShrink: 1,
            }}
          >
            {node.exe}
          </span>
        )}

        {/* Kill actions */}
        {showActions && (
          <div style={{ display: 'flex', gap: '0.25rem', marginLeft: '0.5rem', flexShrink: 0 }}>
            <button
              onClick={(e) => { e.stopPropagation(); onKillPid && onKillPid(node); }}
              disabled={killing}
              title={`Kill PID ${node.pid}`}
              style={{
                padding: '0.2rem 0.4rem',
                background: isFlagged ? 'var(--bg-elevated)' : 'transparent',
                color: isFlagged ? 'var(--warning)' : 'var(--text-tertiary)',
                border: `1px solid ${isFlagged ? 'var(--border-primary)' : 'transparent'}`,
                borderRadius: 'var(--radius-sm)',
                cursor: 'pointer', fontSize: '0.7rem',
                display: 'inline-flex', alignItems: 'center', gap: '0.15rem',
                opacity: isFlagged ? 1 : 0.7,
              }}
            >
              <FiXCircle size={10} />
            </button>
            <button
              onClick={(e) => { e.stopPropagation(); onKillTree && onKillTree(node); }}
              disabled={killing}
              title={`Kill tree PID ${node.pid}`}
              style={{
                padding: '0.2rem 0.4rem',
                background: isFlagged ? 'var(--error-dim)' : 'transparent',
                color: isFlagged ? 'var(--error)' : 'var(--text-tertiary)',
                border: `1px solid ${isFlagged ? 'var(--error)' : 'transparent'}`,
                borderRadius: 'var(--radius-sm)',
                cursor: 'pointer', fontSize: '0.7rem',
                display: 'inline-flex', alignItems: 'center', gap: '0.15rem',
                opacity: isFlagged ? 1 : 0.7,
              }}
            >
              <FiLayers size={10} />
            </button>
          </div>
        )}
      </div>

      {/* ===== Children ===== */}
      {isExpanded && hasChildren && (
        <div style={{
          borderLeft: '1px dashed var(--border-subtle)',
          marginLeft: '7px',
          paddingLeft: '4px',
        }}>
          {node.children.map((child) => (
            <TreeNode
              key={child.pid}
              node={child}
              level={0}
              expandedPids={expandedPids}
              onToggle={onToggle}
              onKillPid={onKillPid}
              onKillTree={onKillTree}
              killing={killing}
              allowKillAll={allowKillAll}
            />
          ))}
        </div>
      )}
    </div>
  );
}

const TreeNode = memo(TreeNodeInner, (prev, next) => {
  return (
    prev.node === next.node &&
    prev.expandedPids === next.expandedPids &&
    prev.killing === next.killing &&
    prev.allowKillAll === next.allowKillAll
  );
});

export default TreeNode;
