import { useCallback, useEffect, useRef, useState } from 'react';
import toast from 'react-hot-toast';
import * as ac from '../../api/accessControl';

const IN_FLIGHT = (b) => ['BLOCKING', 'UNBLOCKING'].includes(b.effective_state) || ['DISPATCHED', 'APPROVED'].includes(b.status)
  || b.unblock?.status === 'DISPATCHED' || b.unblock?.access_state === 'UNVERIFIED';

let mePromise = null;
export function useRole() {
  const [role, setRole] = useState(null);
  useEffect(() => {
    mePromise = mePromise || ac.getMe().catch(() => null);
    mePromise.then((me) => setRole(me?.role || null));
  }, []);
  return { role, isAdmin: role === 'admin', canRequest: role === 'admin' || role === 'operator' };
}

// Success is announced only when the backend reports a newly *verified* state.
function announce(previous, next) {
  if (!previous) return;
  if (previous.effective_state !== 'BLOCKED' && next.effective_state === 'BLOCKED')
    toast.success(`Đã chặn ${next.target_ip} và xác minh rule trên Agent`);
  if (previous.status !== 'FAILED' && next.status === 'FAILED')
    toast.error(`Chặn ${next.target_ip} thất bại: ${next.error?.split(': ').slice(1).join(': ') || 'xem nhật ký'}`);
  if (previous.unblock?.access_state !== 'RESTORED' && next.unblock?.access_state === 'RESTORED')
    toast.success(`Đã khôi phục truy cập cho ${next.target_ip} (có bằng chứng kết nối)`);
  if (previous.effective_state !== 'UNBLOCKED' && next.effective_state === 'UNBLOCKED' && next.unblock?.access_state !== 'RESTORED')
    toast(`Đã gỡ rule chặn ${next.target_ip}; đang chờ client kết nối lại để xác minh`, { icon: 'ℹ️' });
  if (previous.effective_state !== 'UNKNOWN' && next.effective_state === 'UNKNOWN')
    toast(`Chưa xác minh được trạng thái chặn ${next.target_ip}. Bấm "Kiểm tra lại".`, { icon: '⚠️' });
}

export default function useAccessControl(params) {
  const [blocks, setBlocks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(null);
  const previous = useRef({});
  const key = JSON.stringify(params);

  const load = useCallback(async () => {
    try {
      const res = await ac.listBlocks(JSON.parse(key));
      const items = res.items || [];
      items.forEach((b) => announce(previous.current[b.id], b));
      previous.current = Object.fromEntries(items.map((b) => [b.id, b]));
      setBlocks(items);
      setError(null);
    } catch (err) {
      setError(err.message || 'Không tải được danh sách chặn');
    } finally {
      setLoading(false);
    }
  }, [key]);

  useEffect(() => {
    const timer = setTimeout(load, 0);
    return () => clearTimeout(timer);
  }, [load]);
  const polling = blocks.some(IN_FLIGHT);
  useEffect(() => {
    if (!polling) return undefined;
    const timer = setInterval(load, 3000);
    return () => clearInterval(timer);
  }, [polling, load]);

  const run = useCallback(async (id, fn, pending) => {
    setBusy(id);
    try {
      await fn();
      if (pending) toast(pending, { icon: '⏳' });
      await load();
      return true;
    } catch (err) {
      const hint = err.status === 403 ? ' Bạn không có quyền thực hiện thao tác này.'
        : err.status === 409 ? '' : ' Thử lại sau hoặc kiểm tra kết nối.';
      toast.error(`${err.message || 'Thao tác thất bại'}.${hint}`);
      await load();
      return false;
    } finally {
      setBusy(null);
    }
  }, [load]);

  return { blocks, loading, error, busy, reload: load, run };
}
