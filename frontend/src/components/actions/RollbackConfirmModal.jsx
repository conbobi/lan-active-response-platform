// src/components/actions/RollbackConfirmModal.jsx
import React, { useState } from 'react';
import Modal from '../ui/Modal';
import Button from '../ui/Button';
import { FiAlertTriangle, FiRotateCcw } from 'react-icons/fi';

export default function RollbackConfirmModal({ isOpen, onClose, onConfirm, action, isBatch = false, title = 'Confirm Action Rollback' }) {
  const [reason, setReason] = useState('Manual undo via UI');
  const [submitting, setSubmitting] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSubmitting(true);
    try {
      await onConfirm(reason);
      onClose();
    } catch (err) {
      console.error(err);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={title} maxWidth={520}>
      <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-start', background: 'rgba(239, 68, 68, 0.08)', padding: '0.85rem', borderRadius: 'var(--radius-sm)', border: '1px solid rgba(239, 68, 68, 0.25)' }}>
          <FiAlertTriangle size={20} color="var(--error)" style={{ flexShrink: 0, marginTop: '0.15rem' }} />
          <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            {isBatch ? (
              <p>
                Are you sure you want to <strong>undo and revert all active response actions</strong>? This will release network isolation and compensation commands across affected hosts.
              </p>
            ) : (
              <p>
                Are you sure you want to undo action <strong>{action?.id}</strong> ({action?.action_type}) on agent <strong>{action?.agent_id}</strong>? The host state will be restored to its pre-mitigation snapshot.
              </p>
            )}
          </div>
        </div>

        <div>
          <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.4rem' }}>
            Rollback Reason / Audit Justification
          </label>
          <input
            type="text"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="E.g. False positive confirmed, Maintenance complete..."
            required
            style={{
              width: '100%',
              padding: '0.55rem 0.75rem',
              borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--border)',
              background: 'var(--bg-primary)',
              color: 'var(--text-primary)',
              fontSize: '0.875rem',
            }}
          />
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.6rem', marginTop: '0.5rem' }}>
          <Button variant="outline" size="sm" onClick={onClose} disabled={submitting}>
            Cancel
          </Button>
          <Button
            type="submit"
            variant="danger"
            size="sm"
            disabled={submitting || !reason.trim()}
            iconLeft={<FiRotateCcw size={14} />}
          >
            {submitting ? 'Reverting...' : (isBatch ? 'Rollback All Actions' : 'Confirm Rollback')}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
