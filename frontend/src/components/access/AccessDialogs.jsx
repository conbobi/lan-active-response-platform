import { useState } from 'react';
import Modal from '../ui/Modal';
import Button from '../ui/Button';
import { formatTime } from './format';

const label = { color: '#8b949e', fontSize: '0.8rem' };
const value = { color: '#e6edf3', fontSize: '0.85rem', marginBottom: '0.5rem' };

function ReasonBox({ reason, setReason, placeholder }) {
  return (
    <textarea value={reason} onChange={(e) => setReason(e.target.value)} rows={3} placeholder={placeholder}
              style={{ width: '100%', background: '#010409', color: '#e6edf3', border: '1px solid #30363d',
                       borderRadius: '0.4rem', padding: '0.5rem', fontSize: '0.85rem' }} />
  );
}

export function BlockDialog({ open, target, agentId, incidentId, onClose, onConfirm }) {
  const [reason, setReason] = useState('');
  if (!open) return null;
  return (
    <Modal isOpen={open} onClose={onClose} title="Yêu cầu chặn IP trên Agent">
      <div style={label}>IP cần chặn</div><div style={{ ...value, fontFamily: 'monospace' }}>{target?.ip}</div>
      <div style={label}>Agent thực thi</div><div style={value}>{agentId}</div>
      <div style={label}>Incident</div><div style={value}>{incidentId || '—'}</div>
      {target?.basis?.length > 0 && (<>
        <div style={label}>Căn cứ</div>
        <ul style={{ ...value, paddingLeft: '1.1rem' }}>{target.basis.map((b) => <li key={b}>{b}</li>)}</ul>
      </>)}
      <div style={{ ...value, color: '#fbbf24' }}>
        Agent chặn mọi kết nối tới/từ IP này bằng bảng firewall riêng của LARP. Agent tự từ chối nếu IP thuộc kênh quản trị
        (Manager, SSH đang mở, Tailscale). Yêu cầu cần SOC Admin phê duyệt trước khi thực thi.
      </div>
      <div style={label}>Lý do chặn</div>
      <ReasonBox reason={reason} setReason={setReason} placeholder="Ví dụ: reverse shell tới cổng 4444 từ IP này" />
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.75rem' }}>
        <Button variant="ghost" onClick={onClose}>Huỷ</Button>
        <Button disabled={reason.trim().length < 5} onClick={() => onConfirm(reason.trim())}>Gửi yêu cầu chặn</Button>
      </div>
    </Modal>
  );
}

export function UnblockDialog({ open, block, incidentOpen, onClose, onConfirm }) {
  const [reason, setReason] = useState('');
  if (!open || !block) return null;
  return (
    <Modal isOpen={open} onClose={onClose} title="Bỏ chặn IP">
      <div style={label}>IP cần bỏ chặn</div><div style={{ ...value, fontFamily: 'monospace' }}>{block.target_ip}</div>
      <div style={label}>Agent đang thực thi chặn</div><div style={value}>{block.agent_id}</div>
      <div style={label}>Incident liên quan</div><div style={value}>{block.incident_id || '—'}</div>
      <div style={label}>Lý do chặn</div><div style={value}>{block.reason}</div>
      <div style={label}>Thời gian chặn</div><div style={value}>{formatTime(block.verified_at || block.approved_at)}</div>
      <div style={label}>Người phê duyệt chặn</div><div style={value}>{block.approved_by || '—'}</div>
      {incidentOpen && (
        <div style={{ ...value, color: '#f87171' }}>
          Cảnh báo: incident liên quan vẫn đang mở — nguy cơ từ IP này có thể vẫn còn.
        </div>
      )}
      <div style={{ ...value, color: '#8b949e' }}>
        Chỉ gỡ rule của lần chặn này. Truy cập chỉ được báo "đã khôi phục" khi Agent thấy client kết nối lại.
      </div>
      <div style={label}>Lý do bỏ chặn</div>
      <ReasonBox reason={reason} setReason={setReason} placeholder="Ví dụ: đã vá lỗ hổng, cho phép máy lab truy cập lại" />
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.75rem' }}>
        <Button variant="ghost" onClick={onClose}>Huỷ</Button>
        <Button disabled={reason.trim().length < 5} onClick={() => onConfirm(reason.trim())}>Gửi yêu cầu bỏ chặn</Button>
      </div>
    </Modal>
  );
}

export function ConfirmDialog({ open, title, message, confirmLabel, onClose, onConfirm }) {
  if (!open) return null;
  return (
    <Modal isOpen={open} onClose={onClose} title={title} maxWidth={480}>
      <div style={{ ...value, whiteSpace: 'pre-line' }}>{message}</div>
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.75rem' }}>
        <Button variant="ghost" onClick={onClose}>Huỷ</Button>
        <Button onClick={onConfirm}>{confirmLabel}</Button>
      </div>
    </Modal>
  );
}
