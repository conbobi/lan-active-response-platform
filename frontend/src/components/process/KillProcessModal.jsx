import { useState, useEffect } from 'react';
import Modal from '../ui/Modal';
import Button from '../ui/Button';

export default function KillProcessModal({ isOpen, process, agentId, onClose, onConfirm }) {
  const [reason, setReason] = useState("");
  const [killTree, setKillTree] = useState(Boolean(process?.defaultKillTree));
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (isOpen) {
      setReason("");
      setKillTree(Boolean(process?.defaultKillTree));
      setLoading(false);
    }
  }, [isOpen, process]);


  if (!process) return null;

  async function handleConfirm() {
    setLoading(true);
    try {
      await onConfirm({
        pid: process.pid,
        reason: reason || "Manual analyst action",
        killTree,
      });
      onClose();
    } catch (err) {
      // Allow parent error toast to catch, keep modal state or close
      console.error("Kill confirm error:", err);
    } finally {
      setLoading(false);
    }
  }

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="☠️ Kill Process" maxWidth={560}>
      {/* Warning banner */}
      <div
        style={{
          background: 'rgba(239, 68, 68, 0.1)',
          border: '1px solid rgba(239, 68, 68, 0.3)',
          borderRadius: 'var(--radius-sm, 8px)',
          padding: '0.85rem 1rem',
          marginBottom: '1rem',
        }}
      >
        <div style={{ fontWeight: 600, color: 'var(--error, #ef4444)', marginBottom: '0.25rem' }}>
          ⚠️ Hành động không thể hoàn tác
        </div>
        <div style={{ fontSize: '0.875rem', color: 'var(--text-secondary, #64748b)' }}>
          Process sẽ bị kill ngay lập tức trên agent <strong>{agentId}</strong>. Không thể khôi phục.
        </div>
      </div>

      {/* Process info */}
      <div
        style={{
          background: 'var(--bg-secondary, #f8fafc)',
          border: '1px solid var(--border, #e2e8f0)',
          borderRadius: 'var(--radius-sm, 8px)',
          padding: '0.85rem 1rem',
          marginBottom: '1rem',
        }}
      >
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem', fontSize: '0.875rem' }}>
          <div>
            <span style={{ color: 'var(--text-secondary, #64748b)' }}>Name:</span>
            <span style={{ marginLeft: '0.5rem', fontFamily: 'monospace', fontWeight: 600, color: 'var(--text-primary)' }}>
              {process.name}
            </span>
          </div>
          <div>
            <span style={{ color: 'var(--text-secondary, #64748b)' }}>PID:</span>
            <span style={{ marginLeft: '0.5rem', fontFamily: 'monospace', fontWeight: 600, color: 'var(--primary, #6100ff)' }}>
              {process.pid}
            </span>
          </div>
          <div style={{ gridColumn: 'span 2' }}>
            <span style={{ color: 'var(--text-secondary, #64748b)' }}>Path:</span>
            <div
              style={{
                fontFamily: 'monospace',
                fontSize: '0.78rem',
                marginTop: '0.25rem',
                wordBreak: 'break-all',
                color: 'var(--text-primary)',
              }}
            >
              {process.exe || process.exe_path || '(no path)'}
            </div>
          </div>
          {process.cmdline && (
            <div style={{ gridColumn: 'span 2' }}>
              <span style={{ color: 'var(--text-secondary, #64748b)' }}>Cmdline:</span>
              <div
                style={{
                  fontFamily: 'monospace',
                  fontSize: '0.78rem',
                  marginTop: '0.25rem',
                  wordBreak: 'break-all',
                  background: 'var(--bg-card, #ffffff)',
                  padding: '0.5rem',
                  borderRadius: '4px',
                  border: '1px solid var(--border, #e2e8f0)',
                  color: 'var(--text-primary)',
                  maxHeight: '120px',
                  overflowY: 'auto',
                }}
              >
                {process.cmdline}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Kill tree option */}
      <label
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.6rem',
          marginBottom: '1rem',
          cursor: 'pointer',
          fontSize: '0.875rem',
          color: 'var(--text-primary)',
        }}
      >
        <input
          type="checkbox"
          checked={killTree}
          onChange={(e) => setKillTree(e.target.checked)}
          style={{ width: '16px', height: '16px', cursor: 'pointer' }}
        />
        <span>
          Kill cả <strong>process tree</strong> (bao gồm tất cả process con)
        </span>
      </label>

      {/* Reason input */}
      <div style={{ marginBottom: '1.25rem' }}>
        <label
          style={{
            display: 'block',
            fontSize: '0.875rem',
            fontWeight: 500,
            marginBottom: '0.35rem',
            color: 'var(--text-primary)',
          }}
        >
          Lý do (ghi vào audit log):
        </label>
        <input
          type="text"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="VD: Confirmed malware, LOLBin execution..."
          style={{
            width: '100%',
            padding: '0.55rem 0.75rem',
            borderRadius: 'var(--radius-sm, 8px)',
            border: '1px solid var(--border, #cbd5e1)',
            background: 'var(--bg-card, #ffffff)',
            color: 'var(--text-primary)',
            fontSize: '0.875rem',
            outline: 'none',
          }}
        />
      </div>

      {/* Buttons */}
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
        <Button variant="ghost" onClick={onClose} disabled={loading}>
          Hủy
        </Button>
        <Button
          variant="danger"
          onClick={handleConfirm}
          disabled={loading}
        >
          {loading ? "Đang kill..." : "☠️ Xác nhận Kill"}
        </Button>
      </div>
    </Modal>
  );
}
