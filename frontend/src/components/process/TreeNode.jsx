import React, { memo } from 'react';
import { FiXCircle, FiLayers, FiAlertTriangle, FiLock } from 'react-icons/fi';

// ---------------------------------------------------------------------------
// PPL (Protected Process Light) — Windows refuses termination
// ---------------------------------------------------------------------------
const PPL_REGEX =
  /csrss\.exe|wininit\.exe|winlogon\.exe|services\.exe|smss\.exe|lsass\.exe|^System$|^\[?System/i;

// System processes (killable but should look "system")
const SYSTEM_REGEX =
  /svchost\.exe|dwm\.exe|taskhostw\.exe|RuntimeBroker\.exe|spoolsv\.exe|audiodg\.exe|ctfmon\.exe|fontdrvhost\.exe|^System$|^\[System/i;

// User-facing processes
const USER_REGEX =
  /notepad\.exe|msedge\.exe|chrome\.exe|firefox\.exe|Code\.exe|code\.exe|electron\.exe|powershell\.exe|cmd\.exe/i;

// ---------------------------------------------------------------------------
// HARDCODED high-contrast colors (do NOT rely on CSS vars — theme may be dim)
// ---------------------------------------------------------------------------
const COLOR = {
  textBright: '#f1f5f9',    // near-white — for PPL + primary names
  textNormal: '#e5e7eb',    // light gray — for user/system names
  textMuted: '#9ca3af',    // medium gray — for icons
  textError: '#ef4444',
  textPrimary: '#60a5fa',   // light blue
  textPplIcon: '#c4b5fd',   // light purple icon
};

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

  const name = node.name || '';
  const isUserProcess = USER_REGEX.test(name);
  const isSystemProcess = SYSTEM_REGEX.test(name);
  const isProtected = PPL_REGEX.test(name);

  const isFlagged = node.is_suspicious || isUserProcess;
  const showActions = !isProtected && (isFlagged || allowKillAll);

  // -------------------------------------------------------------------------
  // Visual identity — HARDCODED for guaranteed contrast
  // -------------------------------------------------------------------------
  let nameColor = COLOR.textNormal;
  let nameWeight = '600';
  let rowBg = 'transparent';
  let rowBorder = 'transparent';
  let icon = '·';
  let iconColor = COLOR.textMuted;

  if (node.is_suspicious) {
    nameColor = COLOR.textError;
    nameWeight = '700';
    rowBg = 'rgba(239, 68, 68, 0.10)';
    rowBorder = 'rgba(239, 68, 68, 0.45)';
    icon = '⚠';
    iconColor = COLOR.textError;
  } else if (isUserProcess) {
    nameColor = COLOR.textPrimary;
    nameWeight = '600';
    rowBg = 'rgba(79, 172, 254, 0.10)';
    rowBorder = 'rgba(79, 172, 254, 0.35)';
    icon = '◉';
    iconColor = COLOR.textPrimary;
  } else if (isProtected) {
    // PPL — brightest + subtle purple tint to stand out from dark bg
    nameColor = COLOR.textBright;
    nameWeight = '600';
    rowBg = 'rgba(139, 92, 246, 0.10)';
    rowBorder = 'rgba(139, 92, 246, 0.28)';
    icon = '◆';
    iconColor = COLOR.textPplIcon;
  } else if (isSystemProcess) {
    // System (killable) — light gray, readable
    nameColor = COLOR.textNormal;
    nameWeight = '500';
    icon = '◆';
    iconColor = COLOR.textMuted;
  }

  const PPL_BADGE = {
    bg: 'rgba(139, 92, 246, 0.28)',
    fg: '#ddd6fe',
    border: 'rgba(167, 139, 250, 0.75)',
    glow: '0 0 10px rgba(139, 92, 246, 0.45)',
  };

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
          opacity: 1,
        }}
        onMouseEnter={(e) => {
          if (!rowBg || rowBg === 'transparent') {
            e.currentTarget.style.background = 'rgba(255, 255, 255, 0.05)';
          }
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.background = rowBg;
        }}
        onClick={() => hasChildren && onToggle && onToggle(node.pid)}
      >
        {/* Caret */}
        <span
          style={{
            width: '14px',
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: iconColor,
            fontSize: '10px',
            fontWeight: 700,
            flexShrink: 0,
            opacity: 1,
          }}
        >
          {hasChildren ? (isExpanded ? '▼' : '▶') : '·'}
        </span>

        {/* Icon */}
        <span
          style={{
            color: iconColor,
            fontSize: '11px',
            flexShrink: 0,
            fontWeight: 700,
            opacity: 1,
          }}
        >
          {icon}
        </span>

        {/* Name — HARDCODED bright color */}
        <span
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: '0.8rem',
            fontWeight: nameWeight,
            color: nameColor,
            flexShrink: 0,
            opacity: 1,
            textShadow: isProtected ? '0 0 8px rgba(139, 92, 246, 0.35)' : 'none',
          }}
        >
          {name || 'unknown'}
        </span>

        {/* PID badge — force bright */}
        <span
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: '0.7rem',
            padding: '0.1rem 0.4rem',
            background: 'rgba(255, 255, 255, 0.06)',
            color: '#e2e8f0',
            border: '1px solid rgba(255, 255, 255, 0.15)',
            borderRadius: 'var(--radius-sm)',
            flexShrink: 0,
            opacity: 1,
          }}
        >
          PID {node.pid}
        </span>

        {/* PPID — bright enough to read */}
        {node.parent_pid !== null && node.parent_pid !== undefined && (
          <span
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: '0.68rem',
              color: '#94a3b8',
              flexShrink: 0,
              opacity: 1,
            }}
          >
            PPID {node.parent_pid}
          </span>
        )}

        {/* Suspicious badge */}
        {node.is_suspicious && (
          <span
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.2rem',
              padding: '0.1rem 0.45rem',
              fontSize: '0.65rem',
              fontWeight: 700,
              background: 'var(--error-dim)',
              color: 'var(--error)',
              border: '1px solid var(--error)',
              borderRadius: 'var(--radius-full)',
              textTransform: 'uppercase',
              letterSpacing: '0.03em',
              flexShrink: 0,
              boxShadow: '0 0 8px var(--error-glow)',
            }}
          >
            <FiAlertTriangle size={9} /> Suspicious
          </span>
        )}

        {/* PPL badge — bright purple */}
        {isProtected && (
          <span
            title="Protected Process Light (PPL) — Windows refuses termination"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.25rem',
              padding: '0.12rem 0.55rem',
              fontSize: '0.65rem',
              fontWeight: 700,
              background: PPL_BADGE.bg,
              color: PPL_BADGE.fg,
              border: `1px solid ${PPL_BADGE.border}`,
              borderRadius: 'var(--radius-full)',
              textTransform: 'uppercase',
              letterSpacing: '0.05em',
              flexShrink: 0,
              boxShadow: PPL_BADGE.glow,
              opacity: 1,
            }}
          >
            <FiLock size={10} /> PPL
          </span>
        )}

        {/* Executable path — force readable gray */}
        {node.exe && (
          <span
            title={node.exe}
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: '0.7rem',
              color: '#94a3b8',
              marginLeft: 'auto',
              maxWidth: '280px',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
              flexShrink: 1,
              opacity: 1,
            }}
          >
            {node.exe}
          </span>
        )}

        {/* Kill actions */}
        {showActions && (
          <div
            style={{
              display: 'flex',
              gap: '0.25rem',
              marginLeft: '0.5rem',
              flexShrink: 0,
            }}
          >
            <button
              onClick={(e) => {
                e.stopPropagation();
                onKillPid && onKillPid(node);
              }}
              disabled={killing}
              title={`Kill PID ${node.pid}`}
              style={{
                padding: '0.2rem 0.4rem',
                background: isFlagged ? 'var(--bg-elevated)' : 'transparent',
                color: isFlagged ? 'var(--warning)' : '#94a3b8',
                border: `1px solid ${isFlagged ? 'var(--border-primary)' : 'transparent'}`,
                borderRadius: 'var(--radius-sm)',
                cursor: 'pointer',
                fontSize: '0.7rem',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.15rem',
                opacity: isFlagged ? 1 : 0.8,
              }}
            >
              <FiXCircle size={10} />
            </button>
            <button
              onClick={(e) => {
                e.stopPropagation();
                onKillTree && onKillTree(node);
              }}
              disabled={killing}
              title={`Kill tree PID ${node.pid}`}
              style={{
                padding: '0.2rem 0.4rem',
                background: isFlagged ? 'var(--error-dim)' : 'transparent',
                color: isFlagged ? 'var(--error)' : '#94a3b8',
                border: `1px solid ${isFlagged ? 'var(--error)' : 'transparent'}`,
                borderRadius: 'var(--radius-sm)',
                cursor: 'pointer',
                fontSize: '0.7rem',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.15rem',
                opacity: isFlagged ? 1 : 0.8,
              }}
            >
              <FiLayers size={10} />
            </button>
          </div>
        )}
      </div>

      {/* Children */}
      {isExpanded && hasChildren && (
        <div
          style={{
            borderLeft: '1px dashed var(--border-subtle)',
            marginLeft: '7px',
            paddingLeft: '4px',
          }}
        >
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