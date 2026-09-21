// src/components/actions/BulkUndoConfirmModal.jsx
import React, { useState, useEffect } from 'react';
import Modal from '../ui/Modal';
import Button from '../ui/Button';
import {
  FiAlertTriangle,
  FiRotateCcw,
  FiServer,
  FiFileText,
  FiCheckCircle,
  FiLoader,
} from 'react-icons/fi';

export default function BulkUndoConfirmModal({
  isOpen,
  actions = [],
  onClose,
  onConfirm,
  loading = false,
  progress = null, // { current: 1, total: 3 }
}) {
  const [reason, setReason] = useState('Bulk rollback via Actions History');

  useEffect(() => {
    if (isOpen) {
      setReason('Bulk rollback via Actions History');
    }
  }, [isOpen]);

  const count = actions.length;
  const isReasonFilled = reason.trim().length > 0;

  const handleSubmit = (e) => {
    e?.preventDefault();
    if (!isReasonFilled || loading || count === 0) return;
    if (onConfirm) {
      onConfirm(reason.trim());
    }
  };

  if (!isOpen) return null;

  return (
    <Modal
      isOpen={isOpen}
      onClose={loading ? undefined : onClose}
      title="Xác nhận hoàn nguyên hàng loạt (Bulk Rollback)"
      maxWidth={560}
    >
      <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
        {/* Warning Banner */}
        <div
          style={{
            padding: '1rem',
            borderRadius: 'var(--radius-sm, 6px)',
            background: 'rgba(239, 68, 68, 0.1)',
            border: '1px solid var(--error, #ef4444)',
            color: 'var(--error, #ef4444)',
            display: 'flex',
            gap: '0.75rem',
            alignItems: 'flex-start',
          }}
        >
          <FiAlertTriangle size={22} style={{ flexShrink: 0, marginTop: '2px' }} />
          <div>
            <div style={{ fontWeight: 700, fontSize: '0.95rem', marginBottom: '0.2rem' }}>
              ⚠️ Bạn sắp hoàn nguyên {count} actions đã chọn
            </div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
              Hệ thống sẽ gửi lệnh đảo ngược (unisolate, unblock, release quarantine) và khôi phục trạng thái mạng cho các máy trạm mục tiêu.
            </div>
          </div>
        </div>

        {/* List of Affected Actions & Agents */}
        <div>
          <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)', display: 'block', marginBottom: '0.35rem' }}>
            Danh sách actions sẽ được hoàn nguyên ({count} actions):
          </label>
          <div
            style={{
              maxHeight: '140px',
              overflowY: 'auto',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius-xs, 4px)',
              background: 'var(--bg-secondary, #f8fafc)',
              padding: '0.45rem 0.65rem',
              display: 'flex',
              flexDirection: 'column',
              gap: '0.35rem',
            }}
          >
            {actions.map((act) => (
              <div
                key={act.id}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  fontSize: '0.75rem',
                  fontFamily: 'monospace',
                }}
              >
                <span style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                  <FiServer size={12} color="var(--primary)" />
                  <strong>{act.agent_id}</strong> — <span style={{ textTransform: 'uppercase', color: 'var(--error, #ef4444)' }}>{act.action_type}</span>
                </span>
                <span style={{ color: 'var(--text-tertiary)' }}>{act.id}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Reason Field */}
        <div>
          <label
            htmlFor="bulk-undo-reason"
            style={{
              fontSize: '0.8rem',
              fontWeight: 600,
              color: 'var(--text-primary)',
              display: 'flex',
              alignItems: 'center',
              gap: '0.35rem',
              marginBottom: '0.35rem',
            }}
          >
            <FiFileText size={13} color="var(--primary)" /> Lý do hoàn nguyên (Bắt buộc cho Audit Log):
          </label>
          <input
            id="bulk-undo-reason"
            type="text"
            className="input"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Ví dụ: Security incident resolved, false positive..."
            required
            disabled={loading}
            style={{ width: '100%', fontSize: '0.85rem' }}
          />
        </div>

        {/* Progress Bar (Visible during execution) */}
        {loading && progress && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
              <span>Đang hoàn nguyên {progress.current} / {progress.total} actions...</span>
              <span style={{ fontWeight: 700 }}>
                {Math.round((progress.current / (progress.total || 1)) * 100)}%
              </span>
            </div>
            <div
              style={{
                width: '100%',
                height: '6px',
                borderRadius: '3px',
                background: 'var(--border, #e2e8f0)',
                overflow: 'hidden',
              }}
            >
              <div
                style={{
                  width: `${(progress.current / (progress.total || 1)) * 100}%`,
                  height: '100%',
                  background: 'var(--primary, #3b82f6)',
                  transition: 'width 0.2s',
                }}
              />
            </div>
          </div>
        )}

        {/* Buttons */}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.65rem', marginTop: '0.5rem' }}>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={onClose}
            disabled={loading}
          >
            Hủy bỏ
          </Button>

          <Button
            type="submit"
            variant="danger"
            size="sm"
            disabled={!isReasonFilled || loading || count === 0}
            loading={loading}
            iconLeft={<FiRotateCcw size={13} />}
          >
            Rollback {count} Actions
          </Button>
        </div>
      </form>
    </Modal>
  );
}
