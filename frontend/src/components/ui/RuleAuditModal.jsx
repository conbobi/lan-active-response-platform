// src/components/ui/RuleAuditModal.jsx
import React from 'react';
import Modal from './Modal';
import { FiList, FiClock, FiUser, FiActivity } from 'react-icons/fi';

const actionColorMap = {
  CREATE: { bg: 'rgba(0,192,123,0.1)', color: '#00c07b' },
  UPDATE: { bg: 'rgba(59,130,246,0.1)', color: '#3b82f6' },
  DELETE: { bg: 'rgba(239,68,68,0.1)', color: '#ef4444' },
  TOGGLE_STATUS: { bg: 'rgba(245,158,11,0.1)', color: '#f59e0b' },
  IMPORT: { bg: 'rgba(168,85,247,0.1)', color: '#a855f7' },
};

export default function RuleAuditModal({ isOpen, onClose, auditLogs = [] }) {
  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Security Rules Audit Log" maxWidth={720}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>
          Historical track record of rule creations, modifications, deletions, and status toggles for compliance & security governance.
        </p>

        {auditLogs.length === 0 ? (
          <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-tertiary)' }}>
            No audit logs recorded yet.
          </div>
        ) : (
          <div style={{ maxHeight: 380, overflowY: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Action</th>
                  <th>Rule</th>
                  <th>User</th>
                  <th>Details</th>
                  <th>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {auditLogs.map((log) => {
                  const styleInfo = actionColorMap[log.action] || { bg: 'var(--border)', color: 'var(--text-primary)' };
                  return (
                    <tr key={log.id}>
                      <td>
                        <span
                          style={{
                            padding: '0.2rem 0.5rem',
                            borderRadius: 'var(--radius-full)',
                            fontSize: '0.7rem',
                            fontWeight: 700,
                            background: styleInfo.bg,
                            color: styleInfo.color,
                          }}
                        >
                          {log.action}
                        </span>
                      </td>
                      <td style={{ fontWeight: 600, fontSize: '0.82rem' }}>{log.rule_name}</td>
                      <td>
                        <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', display: 'inline-flex', alignItems: 'center', gap: '0.25rem' }}>
                          <FiUser size={11} />
                          {log.user}
                        </span>
                      </td>
                      <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', maxWidth: 220, whiteSpace: 'normal' }}>
                        {log.details}
                      </td>
                      <td>
                        <span style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)' }}>
                          {new Date(log.timestamp).toLocaleString()}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </Modal>
  );
}
