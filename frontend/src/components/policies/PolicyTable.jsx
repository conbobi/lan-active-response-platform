// src/components/policies/PolicyTable.jsx
import React from 'react';
import Button from '../ui/Button';
import Badge from '../ui/Badge';
import {
  FiShield,
  FiEdit2,
  FiTrash2,
  FiPlay,
  FiServer,
  FiUsers,
  FiLock,
  FiSlash,
  FiLayers,
  FiBell,
  FiClock,
} from 'react-icons/fi';

export default function PolicyTable({
  policies = [],
  loading = false,
  groupsMap = {},
  onEdit,
  onDelete,
  onToggleActive,
  onTest,
}) {
  const getActionBadge = (actionType) => {
    switch (actionType) {
      case 'isolate':
        return <Badge status="danger" label="Isolate" showDot={true} />;
      case 'block_ip':
        return <Badge status="warning" label="Block IP" showDot={true} />;
      case 'quarantine':
        return <Badge status="info" label="Quarantine" showDot={true} />;
      case 'alert':
        return <Badge status="neutral" label="Alert Only" showDot={false} />;
      default:
        return <Badge status="neutral" label={actionType} showDot={false} />;
    }
  };

  const getRangeColor = (minScore) => {
    if (minScore >= 85) return 'var(--error, #ef4444)';
    if (minScore >= 70) return '#f97316'; // orange-red
    if (minScore >= 50) return 'var(--warning, #f59e0b)';
    return 'var(--primary, #3b82f6)';
  };

  if (loading && policies.length === 0) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        {[1, 2, 3, 4].map((i) => (
          <div key={i} className="card skeleton" style={{ height: '64px', borderRadius: 'var(--radius-sm)' }} />
        ))}
      </div>
    );
  }

  if (policies.length === 0) {
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
        <FiShield size={42} style={{ color: 'var(--text-tertiary)', opacity: 0.4, marginBottom: '0.75rem' }} />
        <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.35rem' }}>
          Chưa có Response Policy nào
        </h3>
        <p style={{ fontSize: '0.825rem', color: 'var(--text-tertiary)', maxWidth: '420px', margin: '0 auto 1.25rem auto' }}>
          Tạo chính sách đầu tiên để tự động kích hoạt phản ứng (Alert, Block IP, Isolate) khi Risk Score tăng cao.
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
              <th style={{ padding: '0.75rem 1rem', width: '80px' }}>Priority</th>
              <th style={{ padding: '0.75rem 1rem', minWidth: '180px' }}>Policy Name</th>
              <th style={{ padding: '0.75rem 1rem', minWidth: '170px' }}>Risk Range</th>
              <th style={{ padding: '0.75rem 1rem', width: '110px' }}>Action</th>
              <th style={{ padding: '0.75rem 1rem', width: '110px' }}>Scope</th>
              <th style={{ padding: '0.75rem 1rem', minWidth: '130px' }}>Target Group</th>
              <th style={{ padding: '0.75rem 1rem', width: '90px', textAlign: 'center' }}>Active</th>
              <th style={{ padding: '0.75rem 1rem', width: '140px', textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {policies.map((p, idx) => {
              const isGroup = p.scope === 'group';
              const targetName = p.target_group_name || groupsMap[p.target_group_id] || (isGroup ? p.target_group_id : null);
              const rangeColor = getRangeColor(p.min_score);

              // Calculate range bar width & offset
              const leftPct = Math.max(0, Math.min(100, p.min_score));
              const widthPct = Math.max(2, Math.min(100 - leftPct, (p.max_score || 100) - leftPct));

              return (
                <tr
                  key={p.id}
                  style={{
                    borderBottom: idx < policies.length - 1 ? '1px solid var(--border)' : 'none',
                    opacity: p.is_active ? 1 : 0.65,
                    transition: 'background 0.15s, opacity 0.15s',
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.background = 'var(--bg-secondary, #f8fafc)';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.background = 'transparent';
                  }}
                >
                  {/* Priority Badge */}
                  <td style={{ padding: '0.75rem 1rem' }}>
                    <span
                      style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        minWidth: '28px',
                        height: '24px',
                        padding: '0 0.4rem',
                        borderRadius: 'var(--radius-xs, 4px)',
                        background:
                          p.priority >= 30
                            ? 'rgba(239, 68, 68, 0.12)'
                            : p.priority >= 20
                            ? 'rgba(245, 158, 11, 0.12)'
                            : 'rgba(59, 130, 246, 0.12)',
                        color:
                          p.priority >= 30
                            ? 'var(--error, #ef4444)'
                            : p.priority >= 20
                            ? 'var(--warning, #f59e0b)'
                            : 'var(--primary, #3b82f6)',
                        fontWeight: 700,
                        fontSize: '0.8rem',
                        fontFamily: 'monospace',
                      }}
                      title={`Độ ưu tiên: ${p.priority}`}
                    >
                      #{p.priority}
                    </span>
                  </td>

                  {/* Name & Description */}
                  <td style={{ padding: '0.75rem 1rem' }}>
                    <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.85rem' }}>
                      {p.name}
                    </div>
                    {p.description && (
                      <div
                        style={{
                          fontSize: '0.75rem',
                          color: 'var(--text-tertiary)',
                          marginTop: '0.15rem',
                          lineHeight: 1.3,
                          maxWidth: '280px',
                          whiteSpace: 'nowrap',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                        }}
                        title={p.description}
                      >
                        {p.description}
                      </div>
                    )}
                  </td>

                  {/* Risk Range with Visual Bar */}
                  <td style={{ padding: '0.75rem 1rem' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ fontFamily: 'monospace', fontWeight: 700, fontSize: '0.8rem', color: rangeColor }}>
                          {p.min_score} – {p.max_score}
                        </span>
                        <span style={{ fontSize: '0.7rem', color: 'var(--text-tertiary)' }}>score</span>
                      </div>

                      {/* Visual Range Bar (0 - 100 scale) */}
                      <div
                        style={{
                          width: '100%',
                          height: '6px',
                          background: 'var(--border, #e2e8f0)',
                          borderRadius: '3px',
                          position: 'relative',
                          overflow: 'hidden',
                        }}
                        title={`Ngưỡng kích hoạt: ${p.min_score} đến ${p.max_score}`}
                      >
                        <div
                          style={{
                            position: 'absolute',
                            left: `${leftPct}%`,
                            width: `${widthPct}%`,
                            height: '100%',
                            background: rangeColor,
                            borderRadius: '3px',
                          }}
                        />
                      </div>
                    </div>
                  </td>

                  {/* Action Type */}
                  <td style={{ padding: '0.75rem 1rem' }}>
                    {getActionBadge(p.action_type)}
                  </td>

                  {/* Scope */}
                  <td style={{ padding: '0.75rem 1rem' }}>
                    <span
                      style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '0.3rem',
                        fontSize: '0.75rem',
                        fontWeight: 600,
                        padding: '0.2rem 0.5rem',
                        borderRadius: '4px',
                        background: isGroup ? 'rgba(168, 85, 247, 0.1)' : 'rgba(59, 130, 246, 0.1)',
                        color: isGroup ? '#a855f7' : 'var(--primary)',
                      }}
                    >
                      {isGroup ? <FiUsers size={12} /> : <FiServer size={12} />}
                      {p.scope ? p.scope.toUpperCase() : 'AGENT'}
                    </span>
                  </td>

                  {/* Target Group */}
                  <td style={{ padding: '0.75rem 1rem' }}>
                    {isGroup ? (
                      <span style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.8rem' }}>
                        {targetName ? `🏢 ${targetName}` : 'All Groups'}
                      </span>
                    ) : (
                      <span style={{ color: 'var(--text-tertiary)', fontSize: '0.8rem' }}>— (Per Agent)</span>
                    )}
                  </td>

                  {/* Active Toggle */}
                  <td style={{ padding: '0.75rem 1rem', textAlign: 'center' }}>
                    <button
                      type="button"
                      onClick={() => onToggleActive && onToggleActive(p.id, p.is_active)}
                      style={{
                        width: '36px',
                        height: '20px',
                        borderRadius: '10px',
                        background: p.is_active ? 'var(--success, #10b981)' : 'var(--border, #cbd5e1)',
                        border: 'none',
                        cursor: 'pointer',
                        position: 'relative',
                        transition: 'background 0.2s',
                        padding: 0,
                        display: 'inline-block',
                      }}
                      title={p.is_active ? 'Bấm để tạm dừng policy' : 'Bấm để kích hoạt policy'}
                    >
                      <span
                        style={{
                          position: 'absolute',
                          top: '2px',
                          left: p.is_active ? '18px' : '2px',
                          width: '16px',
                          height: '16px',
                          borderRadius: '50%',
                          background: '#ffffff',
                          transition: 'left 0.2s',
                          boxShadow: '0 1px 2px rgba(0,0,0,0.2)',
                        }}
                      />
                    </button>
                  </td>

                  {/* Actions (Test, Edit, Delete) */}
                  <td style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: '0.35rem' }}>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => onTest && onTest(p)}
                        title="Chạy thử nghiệm (Dry-Run Test)"
                        style={{ padding: '0.3rem 0.45rem', color: 'var(--primary)' }}
                      >
                        <FiPlay size={13} />
                      </Button>

                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => onEdit && onEdit(p)}
                        title="Chỉnh sửa chính sách"
                        style={{ padding: '0.3rem 0.45rem' }}
                      >
                        <FiEdit2 size={13} />
                      </Button>

                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => onDelete && onDelete(p)}
                        title="Xóa chính sách"
                        style={{ padding: '0.3rem 0.45rem', color: 'var(--error, #ef4444)' }}
                      >
                        <FiTrash2 size={13} />
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
