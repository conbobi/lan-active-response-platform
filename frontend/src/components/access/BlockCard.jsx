import { useState } from 'react';
import { FiShield, FiUnlock, FiRefreshCw, FiCheck, FiX, FiChevronDown, FiChevronUp } from 'react-icons/fi';
import Button from '../ui/Button';
import { ACTOR_LABEL, EVENT_LABEL, STATE_STYLE, displayState, formatTime } from './format';

function Row({ label, children }) {
  return (
    <div style={{ display: 'contents' }}>
      <div style={{ color: '#8b949e' }}>{label}</div>
      <div style={{ color: '#e6edf3', wordBreak: 'break-word' }}>{children}</div>
    </div>
  );
}

export function StateBadge({ block }) {
  const state = displayState(block);
  const style = STATE_STYLE[state.key] || STATE_STYLE.UNKNOWN;
  const busy = ['BLOCKING', 'UNBLOCKING'].includes(block.effective_state) || block.status === 'DISPATCHED';
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem', padding: '0.2rem 0.65rem',
                   borderRadius: 999, fontSize: '0.78rem', fontWeight: 600, color: style.color, background: style.bg,
                   border: `1px solid ${style.color}55`, whiteSpace: 'nowrap' }}>
      {busy && <FiRefreshCw size={12} className="spin" />}
      {state.label}
    </span>
  );
}

export default function BlockCard({ block, isAdmin, canRequest, busy, onApprove, onReject, onUnblock, onApproveUnblock,
                                    onRejectUnblock, onCheck }) {
  const [history, setHistory] = useState(false);
  const unblock = block.unblock;
  const pendingUnblock = unblock && unblock.status === 'PENDING_APPROVAL';
  const verification = block.verification || {};
  return (
    <div style={{ border: '1px solid #30363d', borderRadius: '0.6rem', padding: '1rem', background: '#0d1117' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          <FiShield color="#f87171" />
          <div>
            <div style={{ fontSize: '0.75rem', color: '#8b949e' }}>IP bị chặn</div>
            <div style={{ fontFamily: 'monospace', fontSize: '1.05rem', color: '#fff' }}>{block.target_ip}</div>
          </div>
        </div>
        <StateBadge block={block} />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '10rem 1fr', gap: '0.35rem 0.75rem', fontSize: '0.82rem',
                    marginTop: '0.85rem' }}>
        <Row label="Agent áp dụng">{block.agent_id}{block.agent_online ? '' : ' (đang offline)'}</Row>
        <Row label="Lớp thực thi">Firewall trên Agent (nftables, bảng riêng của LARP)</Row>
        <Row label="Incident">{block.incident_id || '—'}</Row>
        <Row label="Lý do chặn">{block.reason}</Row>
        <Row label="Yêu cầu bởi">{block.requested_by} · {formatTime(block.created_at)}</Row>
        <Row label="Phê duyệt bởi">{block.approved_by ? `${block.approved_by} · ${formatTime(block.approved_at)}` : 'Chưa phê duyệt'}</Row>
        <Row label="Bắt đầu chặn">{formatTime(block.verified_at)}</Row>
        <Row label="Hết hạn">{block.expires_at ? formatTime(block.expires_at) : 'Không tự hết hạn'}</Row>
        <Row label="Xác minh">
          {verification.rule_verified
            ? `Đã đọc lại rule chặn trên Agent (${formatTime(verification.observed_at)})`
            : block.status === 'PENDING_APPROVAL' ? '—' : 'Chưa có bằng chứng rule đang tồn tại'}
          {verification.traffic_blocked_packets > 0 && (
            <div style={{ color: '#fca5a5' }}>Đã chặn thực tế {verification.traffic_blocked_packets} gói tin từ/đến IP này</div>
          )}
          {verification.rule_verified && verification.management_preserved && (
            <div style={{ color: '#34d399' }}>Kênh quản trị Agent ↔ Manager vẫn hoạt động sau khi chặn</div>
          )}
        </Row>
        {block.error && <Row label="Lỗi"><span style={{ color: '#fb7185' }}>{block.error.split(': ').slice(1).join(': ') || block.error}</span></Row>}
        {unblock && (
          <Row label="Bỏ chặn">
            {unblock.status_label} · {unblock.access_label}
            {unblock.reason && <div style={{ color: '#8b949e' }}>Lý do: {unblock.reason}</div>}
            {unblock.connectivity?.result === 'no_client_traffic_in_window' && (
              <div style={{ color: '#fbbf24' }}>Chưa thấy client kết nối lại trong thời gian xác minh. Hãy thử kết nối từ client rồi bấm "Kiểm tra lại".</div>
            )}
            {unblock.access_state === 'RESTORED' && unblock.connectivity && (
              <div style={{ color: '#34d399' }}>
                Bằng chứng: {unblock.connectivity.packets_from_client > 0 ? `${unblock.connectivity.packets_from_client} gói tin từ client` : ''}
                {unblock.connectivity.http_request ? ` request ${unblock.connectivity.http_request.path} lúc ${formatTime(unblock.connectivity.http_request.at)}` : ''}
              </div>
            )}
          </Row>
        )}
      </div>

      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginTop: '0.9rem' }}>
        {block.can?.approve && isAdmin && (
          <>
            <Button size="sm" disabled={busy} onClick={() => onApprove(block)} iconLeft={<FiCheck size={13} />}>Phê duyệt & chặn</Button>
            <Button size="sm" variant="ghost" disabled={busy} onClick={() => onReject(block)} iconLeft={<FiX size={13} />}>Từ chối</Button>
          </>
        )}
        {block.can?.approve && !isAdmin && <span style={{ fontSize: '0.8rem', color: '#8b949e' }}>Chờ SOC Admin phê duyệt</span>}
        {block.can?.unblock && canRequest && (
          <Button size="sm" variant="secondary" disabled={busy} onClick={() => onUnblock(block)} iconLeft={<FiUnlock size={13} />}>Bỏ chặn</Button>
        )}
        {pendingUnblock && isAdmin && (
          <>
            <Button size="sm" disabled={busy} onClick={() => onApproveUnblock(block)} iconLeft={<FiCheck size={13} />}>Phê duyệt bỏ chặn</Button>
            <Button size="sm" variant="ghost" disabled={busy} onClick={() => onRejectUnblock(block)}>Từ chối bỏ chặn</Button>
          </>
        )}
        {pendingUnblock && !isAdmin && <span style={{ fontSize: '0.8rem', color: '#8b949e' }}>Yêu cầu bỏ chặn chờ SOC Admin phê duyệt</span>}
        {(['BLOCKING', 'UNBLOCKING'].includes(block.effective_state)) && (
          <Button size="sm" variant="secondary" disabled>{block.effective_state === 'BLOCKING' ? 'Đang chặn…' : 'Đang bỏ chặn…'}</Button>
        )}
        {block.effective_state === 'UNBLOCKED' && unblock?.access_state === 'RESTORED' && (
          <Button size="sm" variant="secondary" disabled>Đã bỏ chặn</Button>
        )}
        {block.can?.check && canRequest && (
          <Button size="sm" variant="ghost" disabled={busy || !block.agent_online} onClick={() => onCheck(block)}
                  iconLeft={<FiRefreshCw size={13} />}>Kiểm tra lại</Button>
        )}
        <Button size="sm" variant="ghost" onClick={() => setHistory(!history)}
                iconLeft={history ? <FiChevronUp size={13} /> : <FiChevronDown size={13} />}>Nhật ký</Button>
      </div>

      {history && (
        <ol style={{ margin: '0.75rem 0 0', paddingLeft: '1.1rem', fontSize: '0.8rem', color: '#c9d1d9' }}>
          {(block.history || []).map((h, i) => (
            <li key={i} style={{ marginBottom: '0.25rem' }}>
              <span style={{ color: '#8b949e' }}>{formatTime(h.at)}</span> — {EVENT_LABEL[h.event] || h.event}
              {' '}<span style={{ color: '#8b949e' }}>({ACTOR_LABEL[h.actor] || h.actor})</span>
              {h.detail?.note && <span style={{ color: '#fbbf24' }}> — {h.detail.note}</span>}
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}
