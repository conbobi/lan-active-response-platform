// src/components/actions/AuditLogModal.jsx
import React, { useState, useEffect } from 'react';
import Modal from '../ui/Modal';
import { getActionAuditLogs } from '../../api/actions';
import { FiUser, FiClock } from 'react-icons/fi';
import {
  AUDIT_EVENT_LABELS,
  formatDateTimeVN,
  formatDateTimeUTC,
  shortenId,
  translateActor,
} from '../../i18n/viVN';

export default function AuditLogModal({ isOpen, onClose, actionId }) {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!isOpen || !actionId) return;

    const fetchLogs = async () => {
      setLoading(true);
      try {
        const data = await getActionAuditLogs(actionId);
        setLogs(Array.isArray(data) ? data : []);
        setError(null);
      } catch (err) {
        console.error(err);
        setError(err.message || 'Failed to load audit logs');
      } finally {
        setLoading(false);
      }
    };

    fetchLogs();
  }, [isOpen, actionId]);

  const getEventBadge = (event) => {
    let color = 'var(--text-tertiary)';
    let bg = 'var(--bg-secondary)';
    let border = 'var(--border)';

    if (event === 'created') {
      color = '#3b82f6';
      bg = 'rgba(59, 130, 246, 0.1)';
      border = 'rgba(59, 130, 246, 0.3)';
    } else if (event === 'applied') {
      color = '#f97316';
      bg = 'rgba(249, 115, 22, 0.1)';
      border = 'rgba(249, 115, 22, 0.3)';
    } else if (event.includes('undone')) {
      color = '#22c55e';
      bg = 'rgba(34, 197, 94, 0.1)';
      border = 'rgba(34, 197, 94, 0.3)';
    } else if (event.includes('requested')) {
      color = '#eab308';
      bg = 'rgba(234, 179, 8, 0.1)';
      border = 'rgba(234, 179, 8, 0.3)';
    } else if (event === 'failed') {
      color = '#ef4444';
      bg = 'rgba(239, 68, 68, 0.1)';
      border = 'rgba(239, 68, 68, 0.3)';
    }

    return (
      <span
        style={{
          display: 'inline-block',
          padding: '0.15rem 0.45rem',
          borderRadius: '4px',
          fontSize: '0.72rem',
          fontWeight: 700,
          textTransform: 'uppercase',
          color,
          background: bg,
          border: `1px solid ${border}`,
        }}
      >
        {AUDIT_EVENT_LABELS[event] || event.replaceAll('_', ' ')}
      </span>
    );
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={`Nhật ký kiểm toán hành động: ${shortenId(actionId)}`} maxWidth={680}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
        {loading && (
          <div style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--text-tertiary)', fontSize: '0.85rem' }}>
            Đang tải nhật ký kiểm toán...
          </div>
        )}

        {error && (
          <div style={{ padding: '0.75rem', background: 'rgba(239,68,68,0.1)', color: 'var(--error)', borderRadius: 'var(--radius-sm)', fontSize: '0.85rem' }}>
            {error}
          </div>
        )}

        {!loading && !error && logs.length === 0 && (
          <div style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--text-tertiary)', fontSize: '0.85rem' }}>
            Chưa có bản ghi kiểm toán nào cho hành động này.
          </div>
        )}

        {!loading && logs.length > 0 && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', maxHeight: 420, overflowY: 'auto' }}>
            {logs.map((log) => (
              <div
                key={log.id}
                style={{
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-sm)',
                  padding: '0.75rem 1rem',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.4rem',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    {getEventBadge(log.event)}
                    <span style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                      <FiUser size={13} color="var(--primary)" /> {translateActor(log.actor)}
                    </span>
                  </div>
                  <span
                    style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}
                    title={formatDateTimeUTC(log.created_at)}
                  >
                    <FiClock size={12} /> {formatDateTimeVN(log.created_at)}
                  </span>
                </div>

                {log.reason && (
                  <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                    <strong>Lý do / Diễn giải:</strong> {log.reason}
                  </div>
                )}

                {log.metadata && Object.keys(log.metadata).length > 0 && (
                  <div style={{ fontSize: '0.76rem', color: 'var(--text-secondary)', background: 'var(--bg-primary)', padding: '0.45rem 0.65rem', borderRadius: '4px', display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem' }}>
                      {Object.entries(log.metadata).slice(0, 6).map(([k, v]) => (
                        <span key={k}>
                          <span style={{ color: 'var(--text-tertiary)' }}>{k}:</span>{' '}
                          <code>{typeof v === 'object' ? JSON.stringify(v) : String(v)}</code>
                        </span>
                      ))}
                    </div>
                    <details>
                      <summary style={{ cursor: 'pointer', color: 'var(--text-tertiary)', fontSize: '0.72rem' }}>
                        Xem metadata JSON (nâng cao)
                      </summary>
                      <pre style={{ margin: '0.35rem 0 0 0', fontFamily: 'monospace', whiteSpace: 'pre-wrap' }}>
                        {JSON.stringify(log.metadata, null, 2)}
                      </pre>
                    </details>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </Modal>
  );
}
