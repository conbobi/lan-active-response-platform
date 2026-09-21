// src/components/actions/AuditLogModal.jsx
import React, { useState, useEffect } from 'react';
import Modal from '../ui/Modal';
import { getActionAuditLogs } from '../../api/actions';
import { FiActivity, FiUser, FiClock, FiInfo } from 'react-icons/fi';

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
        {event.replace('_', ' ')}
      </span>
    );
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={`Audit Trail: Action ${actionId}`} maxWidth={650}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
        {loading && (
          <div style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--text-tertiary)', fontSize: '0.85rem' }}>
            Loading audit events...
          </div>
        )}

        {error && (
          <div style={{ padding: '0.75rem', background: 'rgba(239,68,68,0.1)', color: 'var(--error)', borderRadius: 'var(--radius-sm)', fontSize: '0.85rem' }}>
            {error}
          </div>
        )}

        {!loading && !error && logs.length === 0 && (
          <div style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--text-tertiary)', fontSize: '0.85rem' }}>
            No audit logs recorded for this action.
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
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    {getEventBadge(log.event)}
                    <span style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                      <FiUser size={13} color="var(--primary)" /> {log.actor}
                    </span>
                  </div>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                    <FiClock size={12} /> {new Date(log.created_at).toLocaleString()}
                  </span>
                </div>

                {log.reason && (
                  <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                    <strong>Reason:</strong> {log.reason}
                  </div>
                )}

                {log.metadata && Object.keys(log.metadata).length > 0 && (
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', background: 'var(--bg-primary)', padding: '0.4rem 0.6rem', borderRadius: '4px', fontFamily: 'monospace' }}>
                    {JSON.stringify(log.metadata, null, 2)}
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
