// src/components/actions/ActionsTable.jsx
import React from 'react';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import AutoRollbackTimer from './AutoRollbackTimer';
import UndoButton from './UndoButton';
import {
  FiLock,
  FiSlash,
  FiLayers,
  FiShield,
  FiActivity,
  FiServer,
  FiUsers,
  FiClock,
} from 'react-icons/fi';

export default function ActionsTable({
  actions = [],
  selectedIds = new Set(),
  onToggleSelect,
  onSelectAll,
  onUndo,
  onViewLog,
  loading = false,
}) {
  const getActionIcon = (type) => {
    switch (type) {
      case 'isolate':
      case 'auto_isolate':
        return <FiLock size={14} color="var(--error, #ef4444)" />;
      case 'block_ip':
        return <FiSlash size={14} color="var(--warning, #f59e0b)" />;
      case 'quarantine':
        return <FiShield size={14} color="#a855f7" />;
      case 'kill':
      case 'kill_process':
      case 'kill_process_tree':
        return <FiLayers size={14} color="var(--warning, #f59e0b)" />;
      default:
        return <FiActivity size={14} color="var(--primary, #3b82f6)" />;
    }
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'applied':
        return <Badge status="danger" label="Applied" showDot={true} />;
      case 'reverted':
        return <Badge status="active" label="Reverted" showDot={true} />;
      case 'failed':
        return <Badge status="danger" label="Failed" showDot={false} />;
      case 'reverting':
        return <Badge status="warning" label="Reverting..." showDot={true} />;
      default:
        return <Badge status="neutral" label={status || 'Unknown'} showDot={false} />;
    }
  };

  // Only actions with status === 'applied' can be selected for rollback
  const appliedActions = actions.filter((a) => a.status === 'applied');
  const allAppliedSelected =
    appliedActions.length > 0 && appliedActions.every((a) => selectedIds.has(a.id));

  if (loading && actions.length === 0) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        {[1, 2, 3, 4, 5].map((i) => (
          <div key={i} className="card skeleton" style={{ height: '58px', borderRadius: 'var(--radius-sm)' }} />
        ))}
      </div>
    );
  }

  if (actions.length === 0) {
    return (
      <div
        className="card"
        style={{
          padding: '3.5rem 1.5rem',
          textAlign: 'center',
          borderRadius: 'var(--radius-md)',
          background: 'var(--bg-card)',
          border: '1px solid var(--border)',
        }}
      >
        <FiActivity size={40} style={{ color: 'var(--text-tertiary)', opacity: 0.4, marginBottom: '0.75rem' }} />
        <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.35rem' }}>
          Không tìm thấy response action nào
        </h3>
        <p style={{ fontSize: '0.825rem', color: 'var(--text-tertiary)', maxWidth: '420px', margin: '0 auto' }}>
          Các hành động cô lập mạng, chặn IP, cách ly hoặc diệt tiến trình sẽ được tự động ghi lại tại đây.
        </p>
      </div>
    );
  }

  return (
    <div
      style={{
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius-md)',
        overflow: 'hidden',
        background: 'var(--bg-card, #ffffff)',
        boxShadow: 'var(--shadow-sm, 0 1px 2px 0 rgba(0, 0, 0, 0.05))',
      }}
    >
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.825rem' }}>
          <thead>
            <tr
              style={{
                background: 'var(--bg-secondary, #f8fafc)',
                borderBottom: '1px solid var(--border)',
                color: 'var(--text-secondary)',
                fontWeight: 600,
                fontSize: '0.75rem',
                textTransform: 'uppercase',
                letterSpacing: '0.04em',
              }}
            >
              <th style={{ padding: '0.75rem 0.85rem', width: '40px', textAlign: 'center' }}>
                <input
                  type="checkbox"
                  checked={allAppliedSelected}
                  disabled={appliedActions.length === 0}
                  onChange={(e) => onSelectAll && onSelectAll(e.target.checked)}
                  title="Chọn tất cả action đang Applied để hoàn nguyên hàng loạt"
                  style={{ cursor: 'pointer' }}
                />
              </th>
              <th style={{ padding: '0.75rem 0.85rem', minWidth: '150px' }}>Thời gian</th>
              <th style={{ padding: '0.75rem 0.85rem', minWidth: '120px' }}>Action ID</th>
              <th style={{ padding: '0.75rem 0.85rem', minWidth: '150px' }}>Mục tiêu (Target)</th>
              <th style={{ padding: '0.75rem 0.85rem', width: '120px' }}>Loại Action</th>
              <th style={{ padding: '0.75rem 0.85rem', width: '100px' }}>Scope</th>
              <th style={{ padding: '0.75rem 0.85rem', width: '110px' }}>Trạng thái</th>
              <th style={{ padding: '0.75rem 0.85rem', minWidth: '150px' }}>Auto-Rollback</th>
              <th style={{ padding: '0.75rem 0.85rem', width: '140px', textAlign: 'right' }}>Thao tác</th>
            </tr>
          </thead>
          <tbody>
            {actions.map((act, idx) => {
              const isSelected = selectedIds.has(act.id);
              const isApplied = act.status === 'applied';
              const isReverted = act.status === 'reverted';
              const groupName = act.action_params?.group_name;
              const hasGroup = !!(groupName || act.action_params?.group_id);

              const timeDisplay = new Date(act.applied_at || act.created_at || Date.now()).toLocaleString();

              return (
                <tr
                  key={act.id}
                  style={{
                    borderBottom: idx < actions.length - 1 ? '1px solid var(--border)' : 'none',
                    background: isSelected
                      ? 'rgba(59, 130, 246, 0.05)'
                      : isApplied
                      ? 'rgba(239, 68, 68, 0.02)'
                      : 'transparent',
                    transition: 'background 0.15s',
                  }}
                  onMouseEnter={(e) => {
                    if (!isSelected) {
                      e.currentTarget.style.background = 'var(--bg-secondary, #f8fafc)';
                    }
                  }}
                  onMouseLeave={(e) => {
                    if (!isSelected) {
                      e.currentTarget.style.background = isApplied
                        ? 'rgba(239, 68, 68, 0.02)'
                        : 'transparent';
                    }
                  }}
                >
                  {/* Checkbox */}
                  <td style={{ padding: '0.75rem 0.85rem', textAlign: 'center' }}>
                    <input
                      type="checkbox"
                      checked={isSelected}
                      disabled={!isApplied}
                      onChange={() => onToggleSelect && onToggleSelect(act.id)}
                      title={isApplied ? 'Chọn action này' : 'Chỉ có thể chọn action đang Applied'}
                      style={{ cursor: isApplied ? 'pointer' : 'not-allowed' }}
                    />
                  </td>

                  {/* Timestamp */}
                  <td style={{ padding: '0.75rem 0.85rem', whiteSpace: 'nowrap', color: 'var(--text-secondary)', fontSize: '0.78rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                      <FiClock size={12} color="var(--text-tertiary)" />
                      <span>{timeDisplay}</span>
                    </div>
                  </td>

                  {/* Action ID */}
                  <td style={{ padding: '0.75rem 0.85rem', fontFamily: 'monospace', fontWeight: 600, color: 'var(--primary)' }}>
                    {act.id}
                  </td>

                  {/* Target (Agent ID or Group) */}
                  <td style={{ padding: '0.75rem 0.85rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                      <FiServer size={13} color="var(--primary)" />
                      <strong style={{ color: 'var(--text-primary)' }}>{act.agent_id}</strong>
                    </div>
                    {hasGroup && (
                      <div style={{ fontSize: '0.72rem', color: 'var(--text-tertiary)', marginTop: '0.15rem' }}>
                        Nhóm: <strong>{groupName || act.action_params?.group_id}</strong>
                      </div>
                    )}
                  </td>

                  {/* Action Type */}
                  <td style={{ padding: '0.75rem 0.85rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                      {getActionIcon(act.action_type)}
                      <span style={{ fontWeight: 600, textTransform: 'capitalize', color: 'var(--text-primary)' }}>
                        {act.action_type?.replace('_', ' ')}
                      </span>
                    </div>
                  </td>

                  {/* Scope */}
                  <td style={{ padding: '0.75rem 0.85rem' }}>
                    <span
                      style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '0.25rem',
                        fontSize: '0.725rem',
                        fontWeight: 600,
                        padding: '0.15rem 0.45rem',
                        borderRadius: '3px',
                        background: hasGroup ? 'rgba(168, 85, 247, 0.1)' : 'rgba(59, 130, 246, 0.1)',
                        color: hasGroup ? '#a855f7' : 'var(--primary)',
                      }}
                    >
                      {hasGroup ? <FiUsers size={11} /> : <FiServer size={11} />}
                      {hasGroup ? 'Group' : 'Agent'}
                    </span>
                  </td>

                  {/* Status */}
                  <td style={{ padding: '0.75rem 0.85rem' }}>
                    {getStatusBadge(act.status)}
                  </td>

                  {/* Auto-Rollback Timer */}
                  <td style={{ padding: '0.75rem 0.85rem' }}>
                    {isApplied && act.auto_rollback_at ? (
                      <AutoRollbackTimer autoRollbackAt={act.auto_rollback_at} status={act.status} />
                    ) : isReverted ? (
                      <span style={{ fontSize: '0.75rem', color: 'var(--success, #10b981)', display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}>
                        ✓ Đã hoàn nguyên
                      </span>
                    ) : (
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)' }}>—</span>
                    )}
                  </td>

                  {/* Actions (Undo + Log) */}
                  <td style={{ padding: '0.75rem 0.85rem', textAlign: 'right' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: '0.4rem' }}>
                      <UndoButton
                        action={act}
                        onUndo={onUndo}
                        size="sm"
                      />

                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => onViewLog && onViewLog(act.id)}
                        iconLeft={<FiActivity size={12} />}
                        title="Xem nhật ký kiểm toán (Audit Trail)"
                        style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                      >
                        Log
                      </Button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
