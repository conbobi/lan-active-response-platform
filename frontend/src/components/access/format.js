// Display helpers: Vietnamese labels, GMT+7 timestamps, state colours (no enum names shown to users).
export const formatTime = (iso) => {
  if (!iso) return '—';
  return new Intl.DateTimeFormat('vi-VN', {
    timeZone: 'Asia/Ho_Chi_Minh', hour: '2-digit', minute: '2-digit', second: '2-digit',
    day: '2-digit', month: '2-digit', year: 'numeric',
  }).format(new Date(iso)) + ' (GMT+7)';
};

export const STATE_STYLE = {
  PENDING_APPROVAL: { color: '#9ca3af', bg: 'rgba(156,163,175,0.12)' },
  BLOCKING: { color: '#60a5fa', bg: 'rgba(96,165,250,0.14)' },
  UNBLOCKING: { color: '#60a5fa', bg: 'rgba(96,165,250,0.14)' },
  BLOCKED: { color: '#f87171', bg: 'rgba(248,113,113,0.14)' },
  PARTIALLY_BLOCKED: { color: '#fbbf24', bg: 'rgba(251,191,36,0.14)' },
  UNBLOCKED: { color: '#34d399', bg: 'rgba(52,211,153,0.14)' },
  UNKNOWN: { color: '#fbbf24', bg: 'rgba(251,191,36,0.14)' },
  NOT_BLOCKED: { color: '#9ca3af', bg: 'rgba(156,163,175,0.12)' },
  FAILED: { color: '#fb7185', bg: 'rgba(251,113,133,0.16)' },
};

export function displayState(block) {
  if (block.status === 'PENDING_APPROVAL') return { key: 'PENDING_APPROVAL', label: 'Chờ phê duyệt chặn' };
  if (block.status === 'REJECTED') return { key: 'NOT_BLOCKED', label: 'Yêu cầu chặn bị từ chối' };
  if (block.status === 'FAILED' && block.effective_state === 'NOT_BLOCKED') return { key: 'FAILED', label: 'Chặn thất bại — chưa có rule' };
  if (block.effective_state === 'UNBLOCKED') {
    const access = block.unblock?.access_state;
    if (access === 'RESTORED') return { key: 'UNBLOCKED', label: 'Đã bỏ chặn & khôi phục truy cập' };
    if (access === 'STILL_BLOCKED') return { key: 'PARTIALLY_BLOCKED', label: 'Đã gỡ rule này — IP vẫn bị chặn bởi chặn khác' };
    return { key: 'UNKNOWN', label: 'Đã gỡ rule — chưa xác minh kết nối' };
  }
  return { key: block.effective_state, label: block.effective_label };
}

export const EVENT_LABEL = {
  requested: 'Yêu cầu chặn', approved: 'Phê duyệt chặn', rejected: 'Từ chối yêu cầu chặn',
  dispatched: 'Gửi lệnh chặn tới Agent', verified: 'Agent áp dụng và đọc lại rule chặn', failed: 'Agent báo chặn thất bại',
  timeout: 'Chưa nhận phản hồi từ Agent (lệnh có thể đã chạy)', state_blocked: 'Firewall xác nhận đang chặn',
  state_partially_blocked: 'Firewall chỉ còn chặn một chiều', state_not_blocked: 'Firewall không còn rule chặn',
  state_unblocked: 'Firewall xác nhận đã gỡ chặn', unblock_requested: 'Yêu cầu bỏ chặn',
  unblock_approved: 'Phê duyệt bỏ chặn', unblock_rejected: 'Từ chối bỏ chặn', unblock_dispatched: 'Gửi lệnh bỏ chặn tới Agent',
  unblock_verified: 'Agent gỡ rule và xác minh không còn rule', unblock_failed: 'Agent báo bỏ chặn thất bại',
  unblock_timeout: 'Chưa nhận phản hồi bỏ chặn (rule có thể đã được gỡ)', access_restored: 'Client kết nối lại thành công',
};

export const ACTOR_LABEL = { agent: 'Agent', manager: 'Manager' };
