import React, { memo } from 'react';
import { FiChevronDown, FiChevronRight, FiXCircle, FiLayers } from 'react-icons/fi';
import Button from '../ui/Button';

function TreeNodeInner({
  node,
  depth = 0,
  level = 0,
  expandedPids,
  onToggle,
  onKillPid,
  onKillTree,
  killing = false,
}) {
  if (!node) return null;

  const hasChildren = Array.isArray(node.children) && node.children.length > 0;
  const isExpanded = expandedPids ? expandedPids.has(node.pid) : false;
  const indent = level * 20;

  // Highlight explorer + notepad + edge (user-interactive processes)
  const isUserProcess = /explorer\.exe|notepad\.exe|msedge\.exe|chrome\.exe|Code\.exe/i.test(node.name || '');
  const isSusp = Boolean(node.is_suspicious);

  return (
    <div style={{ marginLeft: `${indent}px`, display: 'flex', flexDirection: 'column' }}>
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '0.45rem 0.75rem',
          marginBottom: '0.3rem',
          borderRadius: 'var(--radius-sm, 6px)',
          background: isSusp
            ? 'rgba(239, 68, 68, 0.08)'
            : isUserProcess
            ? 'rgba(59, 130, 246, 0.07)'
            : 'var(--bg-secondary, #1e293b)',
          border: isSusp
            ? '1px solid rgba(239, 68, 68, 0.35)'
            : isUserProcess
            ? '1px solid rgba(59, 130, 246, 0.3)'
            : '1px solid var(--border, #334155)',
          transition: 'background 0.15s ease',
        }}
      >
        {/* Left Side: Expand button & Process details */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            flex: 1,
            overflow: 'hidden',
            cursor: hasChildren ? 'pointer' : 'default',
          }}
          onClick={() => hasChildren && onToggle && onToggle(node.pid)}
        >
          {/* Expand toggle */}
          <span
            style={{
              width: 18,
              height: 18,
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--text-secondary, #94a3b8)',
              flexShrink: 0,
            }}
          >
            {hasChildren ? (
              isExpanded ? (
                <FiChevronDown size={15} color="var(--primary, #3b82f6)" />
              ) : (
                <FiChevronRight size={15} />
              )
            ) : (
              '·'
            )}
          </span>

          {/* Process Name */}
          <span
            style={{
              fontFamily: 'monospace',
              fontSize: '0.85rem',
              fontWeight: isUserProcess || isSusp ? 700 : 600,
              color: isSusp
                ? 'var(--error, #ef4444)'
                : isUserProcess
                ? '#38bdf8'
                : 'var(--text-primary, #f8fafc)',
            }}
          >
            {node.name || 'unknown'}
          </span>

          {/* PID & PPID Badges */}
          <span
            style={{
              fontFamily: 'monospace',
              fontSize: '0.75rem',
              color: 'var(--text-tertiary, #64748b)',
              background: 'rgba(0,0,0,0.2)',
              padding: '2px 5px',
              borderRadius: '4px',
            }}
          >
            PID: {node.pid}
          </span>
          {node.parent_pid !== null && node.parent_pid !== undefined && (
            <span
              style={{
                fontFamily: 'monospace',
                fontSize: '0.72rem',
                color: 'var(--text-tertiary, #64748b)',
              }}
            >
              PPID: {node.parent_pid}
            </span>
          )}

          {/* Suspicious Alert Badge */}
          {isSusp && (
            <span
              style={{
                fontSize: '0.7rem',
                fontWeight: 700,
                background: '#ef4444',
                color: '#ffffff',
                padding: '1px 6px',
                borderRadius: '4px',
                textTransform: 'uppercase',
                letterSpacing: '0.5px',
              }}
            >
              ⚠ Suspicious
            </span>
          )}

          {/* Executable Path */}
          {node.exe && (
            <span
              style={{
                fontSize: '0.75rem',
                color: 'var(--text-tertiary, #94a3b8)',
                fontFamily: 'monospace',
                whiteSpace: 'nowrap',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                maxWidth: 280,
              }}
              title={node.exe}
            >
              {node.exe}
            </span>
          )}
        </div>

        {/* Right Side: Metrics & Termination Actions */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexShrink: 0 }}>
          {node.cpu_percent !== undefined && (
            <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary, #94a3b8)' }}>
              CPU: <strong>{node.cpu_percent}%</strong>
            </span>
          )}
          {node.memory_percent !== undefined && (
            <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary, #94a3b8)' }}>
              RAM: <strong>{node.memory_percent}%</strong>
            </span>
          )}

          {onKillPid && (
            <Button
              variant="ghost"
              size="sm"
              iconLeft={<FiXCircle size={13} />}
              onClick={(e) => {
                e.stopPropagation();
                onKillPid(node);
              }}
              disabled={killing}
              title={`Dừng tiến trình PID ${node.pid}`}
            >
              Kill PID
            </Button>
          )}

          {onKillTree && (
            <Button
              variant={isSusp ? 'danger' : 'outline'}
              size="sm"
              iconLeft={<FiLayers size={13} />}
              onClick={(e) => {
                e.stopPropagation();
                onKillTree(node);
              }}
              disabled={killing}
              title={`Dừng tiến trình PID ${node.pid} và toàn bộ tiến trình con`}
            >
              Kill Tree
            </Button>
          )}
        </div>
      </div>

      {/* Children Nodes Recursion */}
      {isExpanded && hasChildren && (
        <div style={{ display: 'flex', flexDirection: 'column' }}>
          {node.children.map((child) => (
            <TreeNode
              key={child.pid}
              node={child}
              depth={depth + 1}
              level={level + 1}
              expandedPids={expandedPids}
              onToggle={onToggle}
              onKillPid={onKillPid}
              onKillTree={onKillTree}
              killing={killing}
            />
          ))}
        </div>
      )}
    </div>
  );
}

// Memoized TreeNode: only re-render if node reference, expanded state, level, or killing changes
const TreeNode = memo(TreeNodeInner, (prevProps, nextProps) => {
  return (
    prevProps.node === nextProps.node &&
    prevProps.expandedPids === nextProps.expandedPids &&
    prevProps.level === nextProps.level &&
    prevProps.killing === nextProps.killing
  );
});

export default TreeNode;
