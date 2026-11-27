import { useState } from 'react';
import * as ac from '../../api/accessControl';
import BlockCard from './BlockCard';
import { ConfirmDialog, UnblockDialog } from './AccessDialogs';

// Cards with every lifecycle operation; each one asks for confirmation first.
export default function BlockList({ blocks, run, busy, role, incidentOpen }) {
  const [unblocking, setUnblocking] = useState(null);
  const [confirm, setConfirm] = useState(null);

  const ask = (title, message, confirmLabel, action) => setConfirm({ title, message, confirmLabel, action });
  const handlers = {
    onApprove: (b) => ask('Phê duyệt chặn IP', `Agent ${b.agent_id} sẽ chặn mọi kết nối tới/từ ${b.target_ip}.\nLý do: ${b.reason}`,
      'Phê duyệt & chặn', () => run(b.id, () => ac.approveBlock(b.id), 'Đã gửi lệnh chặn tới Agent, đang chờ xác minh…')),
    onReject: (b) => ask('Từ chối yêu cầu chặn', `Từ chối chặn ${b.target_ip}?`, 'Từ chối',
      () => run(b.id, () => ac.rejectBlock(b.id))),
    onUnblock: (b) => setUnblocking(b),
    onApproveUnblock: (b) => ask('Phê duyệt bỏ chặn', `Agent ${b.agent_id} sẽ gỡ rule chặn ${b.target_ip} của lần chặn này.\nLý do: ${b.unblock.reason}`,
      'Phê duyệt bỏ chặn', () => run(b.id, () => ac.decideUnblock(b.unblock.id, 'approve'), 'Đã gửi lệnh bỏ chặn, đang chờ xác minh…')),
    onRejectUnblock: (b) => ask('Từ chối bỏ chặn', `Giữ nguyên chặn ${b.target_ip}?`, 'Từ chối',
      () => run(b.id, () => ac.decideUnblock(b.unblock.id, 'reject'))),
    onCheck: (b) => run(b.id, () => ac.checkBlock(b.id), 'Đã yêu cầu Agent đọc lại firewall…'),
  };

  return (
    <>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        {blocks.map((b) => (
          <BlockCard key={b.id} block={b} isAdmin={role.isAdmin} canRequest={role.canRequest} busy={busy === b.id} {...handlers} />
        ))}
      </div>
      <UnblockDialog open={!!unblocking} block={unblocking} incidentOpen={incidentOpen} onClose={() => setUnblocking(null)}
                     onConfirm={async (reason) => {
                       const b = unblocking;
                       setUnblocking(null);
                       await run(b.id, () => ac.requestUnblock(b.id, reason), 'Đã gửi yêu cầu bỏ chặn, chờ SOC Admin phê duyệt');
                     }} />
      <ConfirmDialog open={!!confirm} {...(confirm || {})} onClose={() => setConfirm(null)}
                     onConfirm={async () => { const c = confirm; setConfirm(null); await c.action(); }} />
    </>
  );
}
