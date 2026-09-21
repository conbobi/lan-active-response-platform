// src/components/groups/IsolateGroupConfirmModal.jsx
import React, { useState, useEffect } from 'react';
import Modal from '../ui/Modal';
import Button from '../ui/Button';
import {
  FiAlertTriangle,
  FiLock,
  FiServer,
  FiClock,
  FiFileText,
  FiCheck,
} from 'react-icons/fi';

export default function IsolateGroupConfirmModal({
  isOpen,
  group,
  onClose,
  onConfirm,
  loading = false,
}) {
  const [confirmName, setConfirmName] = useState('');
  const [reason, setReason] = useState('Security incident response');
  const [autoRollbackSecs, setAutoRollbackSecs] = useState(300);

  const groupName = group?.name || '';
  const members = group?.members || [];
  const memberCount = members.length;

  useEffect(() => {
    if (isOpen) {
      setConfirmName('');
      setReason('Security incident response');
      setAutoRollbackSecs(300);
    }
  }, [isOpen, group]);

  const isNameMatched = confirmName.trim() === groupName.trim();
  const isReasonValid = reason.trim().length > 0;
  const canSubmit = isNameMatched && isReasonValid && !loading && memberCount > 0;

  const handleSubmit = (e) => {
    e?.preventDefault();
    if (!canSubmit) return;
    if (onConfirm) {
      onConfirm({
        reason: reason.trim(),
        autoRollbackSeconds: Number(autoRollbackSecs) || 300,
      });
    }
  };

  if (!group) return null;

  return (
    <Modal
      isOpen={isOpen}
      onClose={loading ? undefined : onClose}
      title="Xác nhận cô lập toàn bộ nhóm máy"
      maxWidth={580}
    >
      <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
        {/* Severity Banner */}
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
          <FiAlertTriangle size={24} style={{ flexShrink: 0, marginTop: '2px' }} />
          <div>
            <div style={{ fontWeight: 700, fontSize: '0.95rem', marginBottom: '0.25rem' }}>
              ⚠️ Bạn sắp cô lập toàn bộ nhóm {groupName}
            </div>
            <div style={{ fontSize: '0.8rem', lineHeight: 1.4, color: 'var(--text-secondary)' }}>
              Tất cả <strong>{memberCount} máy</strong> trong nhóm này sẽ <strong>mất kết nối mạng ngay lập tức</strong> (chặn toàn bộ lưu lượng inbound/outbound ngoại trừ kết nối tới LARP Manager).
            </div>
          </div>
        </div>

        {/* Affected Agents List */}
        <div>
          <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.4rem', display: 'block' }}>
            Danh sách Agents sẽ bị ảnh hưởng ({memberCount} agents):
          </label>
          <div
            style={{
              maxHeight: '120px',
              overflowY: 'auto',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius-xs, 4px)',
              background: 'var(--bg-secondary, #f8fafc)',
              padding: '0.4rem 0.6rem',
              display: 'flex',
              flexDirection: 'column',
              gap: '0.3rem',
            }}
          >
            {members.length === 0 ? (
              <span style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)' }}>Nhóm này hiện chưa có agents nào.</span>
            ) : (
              members.map((m) => (
                <div
                  key={m.agent_id}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    fontSize: '0.75rem',
                    color: 'var(--text-primary)',
                    fontFamily: 'monospace',
                  }}
                >
                  <span style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                    <FiServer size={12} color="var(--primary)" />
                    <strong>{m.agent_id}</strong> ({m.hostname || 'no-hostname'})
                  </span>
                  <span style={{ color: 'var(--text-tertiary)' }}>{m.ip_address || 'N/A'}</span>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Reason Field */}
        <div>
          <label
            htmlFor="isolate-reason"
            style={{
              fontSize: '0.8rem',
              fontWeight: 600,
              color: 'var(--text-primary)',
              marginBottom: '0.35rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.35rem',
            }}
          >
            <FiFileText size={13} color="var(--primary)" /> Lý do phản ứng (Bắt buộc cho Audit Log):
          </label>
          <input
            id="isolate-reason"
            type="text"
            className="input"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Ví dụ: Ransomware propagation detected in HR subnet..."
            required
            disabled={loading}
            style={{ width: '100%', fontSize: '0.85rem' }}
          />
        </div>

        {/* Auto Rollback Seconds Field */}
        <div>
          <label
            htmlFor="auto-rollback-secs"
            style={{
              fontSize: '0.8rem',
              fontWeight: 600,
              color: 'var(--text-primary)',
              marginBottom: '0.35rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.35rem',
            }}
          >
            <FiClock size={13} color="var(--warning)" /> Tự động hoàn nguyên sau (giây):
          </label>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <input
              id="auto-rollback-secs"
              type="number"
              className="input"
              value={autoRollbackSecs}
              onChange={(e) => setAutoRollbackSecs(Math.max(0, parseInt(e.target.value) || 0))}
              min="0"
              step="30"
              disabled={loading}
              style={{ width: '140px', fontSize: '0.85rem' }}
            />
            <span style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)' }}>
              ({Math.round(autoRollbackSecs / 60)} phút. 0 để vô hiệu hóa auto-rollback)
            </span>
          </div>
        </div>

        {/* Type Group Name Verification */}
        <div
          style={{
            padding: '0.85rem',
            borderRadius: 'var(--radius-sm, 6px)',
            background: 'var(--bg-secondary, #f8fafc)',
            border: '1px solid var(--border)',
          }}
        >
          <label
            htmlFor="confirm-group-name"
            style={{
              fontSize: '0.8rem',
              fontWeight: 600,
              color: 'var(--text-primary)',
              marginBottom: '0.35rem',
              display: 'block',
            }}
          >
            Để xác nhận, vui lòng gõ chính xác tên nhóm <strong style={{ color: 'var(--error, #ef4444)' }}>{groupName}</strong>:
          </label>
          <input
            id="confirm-group-name"
            type="text"
            className="input"
            value={confirmName}
            onChange={(e) => setConfirmName(e.target.value)}
            placeholder={`Gõ "${groupName}" vào đây`}
            autoComplete="off"
            disabled={loading}
            style={{
              width: '100%',
              fontSize: '0.85rem',
              borderColor: confirmName && !isNameMatched ? 'var(--error, #ef4444)' : undefined,
            }}
          />
          {confirmName && !isNameMatched && (
            <span style={{ color: 'var(--error, #ef4444)', fontSize: '0.725rem', marginTop: '0.25rem', display: 'block' }}>
              Tên chưa khớp với "{groupName}"
            </span>
          )}
        </div>

        {/* Buttons */}
        <div
          style={{
            display: 'flex',
            justifyContent: 'flex-end',
            gap: '0.65rem',
            marginTop: '0.5rem',
          }}
        >
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
            disabled={!canSubmit}
            loading={loading}
            iconLeft={<FiLock size={13} />}
          >
            🛑 Isolate {memberCount} Agents
          </Button>
        </div>
      </form>
    </Modal>
  );
}
