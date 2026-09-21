// src/components/groups/GroupAuditTab.jsx
import React, { useState, useEffect, useCallback } from 'react';
import { getGroupActions } from '../../api/groups';
import { getActionAuditLogs } from '../../api/actions';
import Button from '../ui/Button';
import Badge from '../ui/Badge';
import {
  FiActivity,
  FiClock,
  FiUser,
  FiServer,
  FiRefreshCw,
  FiAlertCircle,
  FiCheckCircle,
  FiRotateCcw,
  FiLock,
  FiLoader,
} from 'react-icons/fi';

export default function GroupAuditTab({ groupId, refreshTrigger }) {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchAuditTrail = useCallback(async () => {
    if (!groupId) return;
    setLoading(true);
    try {
      // 1. Lấy tất cả actions của group
      const actions = await getGroupActions(groupId);
      if (!actions || actions.length === 0) {
        setLogs([]);
        setLoading(false);
        return;
      }

      // 2. Fetch audit logs cho từng action
      const logPromises = actions.map(async (act) => {
        try {
          const auditEntries = await getActionAuditLogs(act.id);
          if (!Array.isArray(auditEntries)) return [];
          return auditEntries.map((entry) => ({
            ...entry,
            agent_id: act.agent_id,
            action_type: act.action_type,
            action_status: act.status,
          }));
        } catch (err) {
          console.warn(`Failed to fetch audit logs for action ${act.id}`, err);
          return [];
        }
      });

      const results = await Promise.all(logPromises);
      const allEntries = results.flat();

      // 3. Sắp xếp theo thời gian mới nhất trước (hoặc cũ nhất trước)
      allEntries.sort((a, b) => {
        const timeA = new Date(a.created_at || 0).getTime();
        const timeB = new Date(b.created_at || 0).getTime();
        return timeB - timeA;
      });

      setLogs(allEntries);
      setError(null);
    } catch (err) {
      console.error(`Failed to fetch group audit logs for ${groupId}`, err);
      setError(err.message || 'Không thể tải lịch sử audit của nhóm');
    } finally {
      setLoading(false);
    }
  }, [groupId]);

  useEffect(() => {
    fetchAuditTrail();
  }, [fetchAuditTrail, refreshTrigger]);

  const getEventBadge = (event) => {
    switch (event) {
      case 'created':
        return <Badge status="info" label="Created" showDot={false} />;
      case 'applied':
        return <Badge status="danger" label="Applied" showDot={true} />;
      case 'undo_requested':
        return <Badge status="warning" label="Undo Requested" showDot={true} />;
      case 'undone':
      case 'auto_undone':
        return <Badge status="active" label={event === 'auto_undone' ? 'Auto Reverted' : 'Reverted'} showDot={true} />;
      case 'failed':
        return <Badge status="danger" label="Failed" showDot={false} />;
      default:
        return <Badge status="neutral" label={event} showDot={false} />;
    }
  };

  const formatEventText = (entry) => {
    const actionLabel = (entry.action_type || 'action').replace('_', ' ');
    const agentLabel = entry.agent_id ? `on ${entry.agent_id}` : '';

    switch (entry.event) {
      case 'created':
        return `Action created (${actionLabel} ${agentLabel})`;
      case 'applied':
        return `Action applied (${actionLabel} ${agentLabel})`;
      case 'undo_requested':
        return `Undo requested ${entry.reason ? `(reason: "${entry.reason}")` : ''}`;
      case 'undone':
        return `Action reverted (${actionLabel} ${agentLabel}) ${entry.reason ? `— ${entry.reason}` : ''}`;
      case 'auto_undone':
        return `Auto rollback completed (timeout expired for ${actionLabel} ${agentLabel})`;
      case 'failed':
        return `Action execution failed: ${entry.reason || 'Unknown error'}`;
      default:
        return `${entry.event} ${entry.reason ? `(${entry.reason})` : ''}`;
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)' }}>
            Group Audit Trail ({logs.length} sự kiện)
          </span>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', margin: '0.15rem 0 0 0' }}>
            Nhật ký kiểm toán lưu vết toàn bộ chu kỳ phản ứng (tạo, áp dụng, yêu cầu hoàn nguyên, khôi phục).
          </p>
        </div>

        <Button
          variant="outline"
          size="sm"
          onClick={fetchAuditTrail}
          disabled={loading}
          iconLeft={<FiRefreshCw size={12} className={loading ? 'animate-spin' : ''} />}
        >
          Làm mới
        </Button>
      </div>

      {error && (
        <div
          style={{
            padding: '0.65rem 0.85rem',
            background: 'rgba(239, 68, 68, 0.1)',
            border: '1px solid var(--error, #ef4444)',
            borderRadius: 'var(--radius-sm, 4px)',
            color: 'var(--error, #ef4444)',
            fontSize: '0.8rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
          }}
        >
          <FiAlertCircle size={15} />
          <span>{error}</span>
        </div>
      )}

      {loading ? (
        <div style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-tertiary)', fontSize: '0.85rem' }}>
          <FiLoader size={20} className="animate-spin" style={{ display: 'inline-block', marginBottom: '0.4rem' }} />
          <div>Đang tổng hợp nhật ký audit log của nhóm...</div>
        </div>
      ) : logs.length === 0 ? (
        <div
          style={{
            padding: '3rem 1.5rem',
            textAlign: 'center',
            background: 'var(--bg-secondary, #f8fafc)',
            borderRadius: 'var(--radius-sm, 6px)',
            border: '1px dashed var(--border)',
          }}
        >
          <FiActivity size={36} style={{ color: 'var(--text-tertiary)', opacity: 0.5, marginBottom: '0.5rem' }} />
          <h4 style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)', margin: '0 0 0.25rem 0' }}>
            Chưa có hoạt động audit nào
          </h4>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-tertiary)', margin: 0 }}>
            Nhật ký kiểm toán sẽ tự động ghi nhận khi có hành động phản ứng hoặc hoàn nguyên trong nhóm.
          </p>
        </div>
      ) : (
        <div
          style={{
            background: 'var(--bg-secondary, #f8fafc)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius-sm, 6px)',
            padding: '1rem',
            maxHeight: '400px',
            overflowY: 'auto',
          }}
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
            {logs.map((entry) => {
              const timeStr = entry.created_at
                ? new Date(entry.created_at).toLocaleTimeString()
                : '--:--:--';
              const dateStr = entry.created_at
                ? new Date(entry.created_at).toLocaleDateString()
                : '';

              return (
                <div
                  key={entry.id}
                  style={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    justifyContent: 'space-between',
                    padding: '0.6rem 0.8rem',
                    background: 'var(--bg-card, #ffffff)',
                    border: '1px solid var(--border)',
                    borderRadius: 'var(--radius-xs, 4px)',
                    gap: '0.75rem',
                    fontSize: '0.8rem',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.65rem', flex: 1 }}>
                    <div
                      style={{
                        fontFamily: 'monospace',
                        color: 'var(--text-tertiary)',
                        fontSize: '0.75rem',
                        whiteSpace: 'nowrap',
                        marginTop: '2px',
                      }}
                      title={`${dateStr} ${timeStr}`}
                    >
                      [{timeStr}]
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                        <span
                          style={{
                            fontWeight: 700,
                            color: entry.actor === 'system' ? 'var(--text-secondary)' : 'var(--primary)',
                            fontFamily: 'monospace',
                            fontSize: '0.75rem',
                            padding: '0.1rem 0.35rem',
                            borderRadius: '3px',
                            background: 'var(--bg-secondary, #f1f5f9)',
                          }}
                        >
                          {entry.actor || 'system'}
                        </span>
                        <span style={{ color: 'var(--text-tertiary)' }}>→</span>
                        <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                          {formatEventText(entry)}
                        </span>
                      </div>

                      {entry.reason && entry.event !== 'undo_requested' && entry.event !== 'undone' && (
                        <div style={{ fontSize: '0.725rem', color: 'var(--text-secondary)', fontStyle: 'italic' }}>
                          Lý do: "{entry.reason}"
                        </div>
                      )}
                    </div>
                  </div>

                  <div style={{ flexShrink: 0 }}>
                    {getEventBadge(entry.event)}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
