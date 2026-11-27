import { useCallback, useEffect, useRef, useState } from 'react';
import toast from 'react-hot-toast';
import { FiAlertOctagon, FiFileText, FiCpu, FiGlobe, FiShield, FiLink } from 'react-icons/fi';
import Button from '../ui/Button';
import Modal from '../ui/Modal';
import { getContainment, requestContainment, decideContainment } from '../../api/containment';
import { requestBlock } from '../../api/accessControl';
import { useRole } from '../access/useAccessControl';
import { formatTime } from '../access/format';

// Intrusion response for one incident: correlated evidence, suspicious file, processes, control channel
// and the state of every response action — all as reported and verified by the Manager/Agent.
const STAGE = {
  auth_bypass: 'Đăng nhập vượt xác thực', suspicious_upload: 'Upload file đáng ngờ', command_injection: 'Command injection',
  web_spawned_shell: 'Web process sinh shell', uploaded_file_execution: 'Thực thi file đáng ngờ',
  outbound_connection: 'Kết nối điều khiển ngược', privileged_execution: 'Thực thi quyền root',
};
const STAGE_STATE = { OBSERVED: ['Quan sát trực tiếp', '#f87171'], CORRELATED: ['Liên kết bằng chứng', '#fbbf24'], NOT_OBSERVED: ['Chưa quan sát', '#6e7681'] };
const FILE_STATE = {
  UPLOADED: 'Đã upload, chưa thấy thực thi', SUSPICIOUS: 'Đáng ngờ', EXECUTION_OBSERVED: 'Đã thấy tiến trình chạy file',
  QUARANTINED: 'Đã cách ly & xác minh', RESTORED: 'Đã khôi phục',
  FILE_UPLOADED: 'Đã upload, chưa thấy thực thi', FILE_SUSPICIOUS: 'Đáng ngờ',
  FILE_EXECUTION_OBSERVED: 'Đã thấy tiến trình chạy file', FILE_EXECUTION_CORRELATED: 'Đã tương quan upload & thực thi',
  FILE_QUARANTINED: 'Đã cách ly & xác minh', FILE_REMOVED: 'Không còn trên ổ đĩa',
};
const ACTION_COLOR = {
  PENDING_APPROVAL: '#9ca3af', DISPATCHED: '#60a5fa', SUCCEEDED: '#60a5fa', VERIFIED: '#34d399', FAILED: '#fb7185',
  REJECTED: '#9ca3af', TIMEOUT: '#fbbf24', VERIFICATION_FAILED: '#fb7185', ROLLED_BACK: '#a3a3a3',
};
const EVENT = {
  requested: 'Yêu cầu', approved: 'Phê duyệt', rejected: 'Từ chối', dispatched: 'Gửi lệnh tới Agent', verified: 'Agent thực hiện và xác minh',
  agent_result: 'Agent trả kết quả', timeout: 'Chưa nhận phản hồi (lệnh có thể đã chạy)', preserved: 'Đã đóng gói bằng chứng', restored: 'Đã khôi phục',
};
const box = { border: '1px solid #30363d', borderRadius: '0.6rem', padding: '0.85rem 1rem', background: '#0d1117' };
const title = { display: 'flex', alignItems: 'center', gap: '0.45rem', color: '#e6edf3', fontWeight: 700, marginBottom: '0.5rem' };

function ReasonDialog({ dialog, onClose }) {
  const [reason, setReason] = useState(dialog?.reason || '');
  if (!dialog) return null;
  return (
    <Modal isOpen onClose={onClose} title={dialog.title} maxWidth={520}>
      <div style={{ fontSize: '0.85rem', color: '#e6edf3', whiteSpace: 'pre-line', marginBottom: '0.6rem' }}>{dialog.message}</div>
      {dialog.warning && <div style={{ fontSize: '0.82rem', color: '#fbbf24', marginBottom: '0.6rem' }}>{dialog.warning}</div>}
      {dialog.needsReason && (
        <textarea value={reason} onChange={(e) => setReason(e.target.value)} rows={3} placeholder="Lý do"
                  style={{ width: '100%', background: '#010409', color: '#e6edf3', border: '1px solid #30363d', borderRadius: '0.4rem', padding: '0.5rem' }} />
      )}
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.75rem' }}>
        <Button variant="ghost" onClick={onClose}>Huỷ</Button>
        <Button disabled={dialog.needsReason && reason.trim().length < 5} onClick={() => { onClose(); dialog.onConfirm(reason.trim()); }}>
          {dialog.confirmLabel}
        </Button>
      </div>
    </Modal>
  );
}

function Badge({ color, children }) {
  return <span style={{ fontSize: '0.75rem', fontWeight: 600, color, border: `1px solid ${color}66`, borderRadius: 999,
                         padding: '0.1rem 0.55rem', whiteSpace: 'nowrap' }}>{children}</span>;
}

export default function ContainmentPanel({ incidentId, onOpenIncident }) {
  const role = useRole();
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [dialog, setDialog] = useState(null);
  const [busy, setBusy] = useState(false);
  const previous = useRef({});

  const load = useCallback(async () => {
    try {
      const next = await getContainment(incidentId);
      (next.actions || []).forEach((a) => {
        const before = previous.current[a.id];
        if (before && before !== 'VERIFIED' && a.status === 'VERIFIED') toast.success(`${a.kind_label}: đã thực hiện và xác minh`);
        if (before && before !== 'FAILED' && a.status === 'FAILED') toast.error(`${a.kind_label} thất bại`);
      });
      previous.current = Object.fromEntries((next.actions || []).map((a) => [a.id, a.status]));
      setData(next);
      setError(null);
    } catch (err) {
      setError(err.message);
    }
  }, [incidentId]);

  useEffect(() => { const t = setTimeout(load, 0); return () => clearTimeout(t); }, [load]);
  const inFlight = data?.actions?.some((a) => a.status === 'DISPATCHED');
  useEffect(() => {
    if (!inFlight) return undefined;
    const timer = setInterval(load, 3000);
    return () => clearInterval(timer);
  }, [inFlight, load]);

  const run = async (fn, pending) => {
    setBusy(true);
    try {
      await fn();
      if (pending) toast(pending, { icon: '⏳' });
    } catch (err) {
      toast.error(err.status === 403 ? 'Bạn không có quyền thực hiện thao tác này' : err.message || 'Thao tác thất bại');
    } finally {
      setBusy(false);
      load();
    }
  };

  if (error) return <div style={{ ...box, color: '#fb7185', marginBottom: '1rem' }}>Không tải được dữ liệu ứng phó: {error}</div>;
  if (!data) return null;
  if (!data.is_chain) {
    if (!data.correlated_chain) return null;
    const inferred = data.correlated_chain.link === 'INFERRED';
    return (
      <div style={{ ...box, borderColor: '#fbbf2466', marginBottom: '1rem', fontSize: '0.85rem', color: '#e6edf3' }}>
        <FiLink style={{ marginRight: 6 }} />
        Incident này {inferred ? 'có thể thuộc' : 'thuộc'} chuỗi xâm nhập <strong>{data.correlated_chain.incident_id}</strong>
        {inferred ? ' (suy luận theo thời gian và web service, chưa xác nhận bằng PID)' : ''}. Xử lý ứng phó tại incident chuỗi.
        {onOpenIncident && <Button size="sm" variant="ghost" style={{ marginLeft: 8 }} onClick={() => onOpenIncident(data.correlated_chain.incident_id)}>Mở incident chuỗi</Button>}
      </div>
    );
  }

  const caps = data.capabilities || {};
  const canAct = role.canRequest && data.agent_online;
  const actionsFor = (kind, key) => data.actions.filter((a) => a.kind === kind && key(a.target));
  const ask = (opts) => setDialog(opts);
  const req = (kind, target, label) => ask({
    title: label, needsReason: true, confirmLabel: 'Gửi yêu cầu', message: kindMessage(kind, target),
    warning: kind === 'quarantine_file' ? 'Cách ly file không ngắt tiến trình đang chạy từ file đó; hãy xử lý tiến trình/kết nối riêng.' : null,
    onConfirm: (reason) => run(() => requestContainment(incidentId, kind, target, reason),
      ['inspect_file', 'collect_process_evidence'].includes(kind) ? 'Đang thu thập bằng chứng…' : 'Đã tạo đề xuất, chờ SOC Admin phê duyệt'),
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginBottom: '1rem' }}>
      <ReasonDialog dialog={dialog} onClose={() => setDialog(null)} />
      <div style={box}>
        <div style={title}><FiAlertOctagon color="#f87171" /> Phát hiện xâm nhập · {data.agent_id}
          <Badge color={data.severity === 'critical' ? '#f87171' : '#fbbf24'}>{data.severity === 'critical' ? 'Nghiêm trọng' : data.severity}</Badge>
          {!data.agent_online && <Badge color="#fbbf24">Agent offline — chỉ xem</Badge>}
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
          {data.stages.map((s) => {
            const [label, color] = STAGE_STATE[s.status] || STAGE_STATE.NOT_OBSERVED;
            return <span key={s.id} title={s.detail} style={{ fontSize: '0.78rem', border: `1px solid ${color}66`, color, borderRadius: '0.4rem', padding: '0.2rem 0.5rem' }}>
              {STAGE[s.id] || s.id} · {label}</span>;
          })}
        </div>
        {data.inferred_requests.map((r) => (
          <div key={r.evidence_id} style={{ fontSize: '0.78rem', color: '#8b949e', marginTop: '0.4rem' }}>
            Suy luận: request {r.method} {r.path} (HTTP {r.status}) có thể đã khởi chạy shell PID {r.shell_pid}.
          </div>
        ))}
        <div style={{ marginTop: '0.6rem' }}>
          <Button size="sm" variant="ghost" disabled={!canAct || busy} onClick={() => req('collect_process_evidence', {}, 'Bảo toàn bằng chứng')}>
            Bảo toàn bằng chứng (tiến trình, kết nối, file)
          </Button>
        </div>
      </div>

      {data.files.length > 0 && (
        <div style={box}>
          <div style={title}><FiFileText color="#fbbf24" /> File đáng ngờ</div>
          {data.files.map((f) => {
            const inspecting = actionsFor('inspect_file', (t) => t.path === f.path).some((a) => a.status === 'DISPATCHED');
            const quarantine = actionsFor('quarantine_file', (t) => t.path === f.path).at(-1);
            return (
              <div key={f.path} style={{ fontSize: '0.83rem', color: '#e6edf3', marginBottom: '0.6rem' }}>
                <div style={{ fontFamily: 'monospace' }}>{f.path}</div>
                <div style={{ color: '#8b949e' }}>
                  SHA-256: {f.sha256 ? <span style={{ fontFamily: 'monospace' }}>{f.sha256.slice(0, 16)}…</span> : 'chưa thu thập'} ·
                  {' '}Trạng thái: {FILE_STATE[f.state === 'RESTORED' ? 'RESTORED' : (f.file_status || f.state)] || f.file_status || f.state}
                  {f.inspection && <> · Chủ sở hữu: {f.inspection.owner?.user ?? f.inspection.owner?.uid} · Quyền: {f.inspection.mode} · {f.inspection.exists ? `${f.inspection.size} byte` : 'không còn ở vị trí gốc'}</>}
                </div>
                <div style={{ display: 'flex', gap: '0.4rem', marginTop: '0.35rem', flexWrap: 'wrap' }}>
                  {caps.inspect_file && <Button size="sm" variant="ghost" disabled={!canAct || busy || inspecting}
                    onClick={() => req('inspect_file', { path: f.path }, 'Thu thập bằng chứng file')}>{inspecting ? 'Đang thu thập…' : 'Thu thập bằng chứng'}</Button>}
                  {caps.quarantine_file && f.state !== 'QUARANTINED' && (!quarantine || ['FAILED', 'REJECTED', 'ROLLED_BACK'].includes(quarantine.status)) && (
                    <Button size="sm" disabled={!canAct || busy || !f.sha256} onClick={() => req('quarantine_file', { path: f.path }, 'Đề xuất cách ly file')}>
                      {f.sha256 ? 'Đề xuất cách ly' : 'Cần thu thập SHA-256 trước'}</Button>)}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {data.processes.length > 0 && (
        <div style={box}>
          <div style={title}><FiCpu color="#60a5fa" /> Tiến trình liên quan</div>
          {data.processes.map((p) => {
            const pending = actionsFor('terminate_process', (t) => t.pid === p.pid).some((a) => ['PENDING_APPROVAL', 'DISPATCHED'].includes(a.status));
            return (
              <div key={`${p.pid}-${p.process_start_time}`} style={{ fontSize: '0.83rem', color: '#e6edf3', marginBottom: '0.5rem' }}>
                <span style={{ fontFamily: 'monospace' }}>PID {p.pid}</span> · {p.exe} · cha PID {p.parent_pid} ·
                {' '}người dùng: {p.euid === 0 ? 'root' : p.euid ?? 'chưa rõ'} · <Badge color={p.live.state === 'RUNNING' ? '#f87171' : p.live.state === 'EXITED' ? '#34d399' : '#fbbf24'}>{p.live.label}</Badge>
                <div style={{ color: '#8b949e', fontFamily: 'monospace', fontSize: '0.78rem' }}>{p.cmdline}</div>
                {caps.terminate_process && p.live.state === 'RUNNING' && (
                  <Button size="sm" style={{ marginTop: '0.3rem' }} disabled={!canAct || busy || pending}
                    onClick={() => req('terminate_process', { pid: p.pid, process_start_time: p.process_start_time }, 'Đề xuất dừng tiến trình')}>
                    {pending ? 'Đã có đề xuất đang xử lý' : 'Đề xuất dừng tiến trình'}</Button>)}
              </div>
            );
          })}
        </div>
      )}

      {data.network.length > 0 && (
        <div style={box}>
          <div style={title}><FiGlobe color="#f87171" /> Kết nối điều khiển</div>
          {data.network.map((n) => {
            const ip = n.dst.split(':')[0];
            const blocked = data.ip_blocks.some((b) => b.target_ip === ip && !['UNBLOCKED', 'NOT_BLOCKED'].includes(b.effective_state));
            return (
              <div key={n.flow_id || n.dst} style={{ fontSize: '0.83rem', color: '#e6edf3', marginBottom: '0.5rem' }}>
                {n.src} → <strong>{n.dst}</strong> · PID {n.pid}{n.socket_stdio ? ' · stdin/stdout gắn vào socket' : ''} ·
                {' '}<Badge color={n.live.state === 'ESTABLISHED' ? '#f87171' : '#9ca3af'}>{n.live.label}</Badge>
                {caps.block_ip && !blocked && (
                  <Button size="sm" style={{ marginLeft: '0.5rem' }} disabled={!canAct || busy}
                    onClick={() => ask({ title: 'Đề xuất chặn IP', needsReason: true, confirmLabel: 'Gửi yêu cầu chặn',
                      message: `Chặn mọi kết nối tới/từ ${ip} trên Agent ${data.agent_id}. Agent tự từ chối nếu IP thuộc kênh quản trị.`,
                      onConfirm: (reason) => run(() => requestBlock({ agent_id: data.agent_id, target_ip: ip, incident_id: incidentId, reason }),
                        'Đã tạo yêu cầu chặn, chờ SOC Admin phê duyệt') })}>Đề xuất chặn IP</Button>)}
                {blocked && <span style={{ marginLeft: 8, color: '#8b949e' }}>Đã có yêu cầu/chặn — xem mục Kiểm soát truy cập</span>}
              </div>
            );
          })}
        </div>
      )}

      {data.actions.length > 0 && (
        <div style={box}>
          <div style={title}><FiShield color="#34d399" /> Trạng thái ứng phó</div>
          {data.actions.map((a) => (
            <div key={a.id} style={{ fontSize: '0.82rem', color: '#e6edf3', padding: '0.45rem 0', borderTop: '1px solid #21262d' }}>
              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
                <strong>{a.kind_label}</strong>
                <span style={{ fontFamily: 'monospace', color: '#8b949e' }}>{a.target.path || (a.target.pid ? `PID ${a.target.pid}` : '')}</span>
                <Badge color={ACTION_COLOR[a.status] || '#9ca3af'}>{a.status_label}</Badge>
                {a.command_id && <span style={{ fontFamily: 'monospace', fontSize: '0.74rem', color: '#8b949e' }}>cmd: {a.command_id}</span>}
                {a.status === 'PENDING_APPROVAL' && role.isAdmin && (<>
                  <Button size="sm" disabled={busy || !data.agent_online} onClick={() => ask({ title: `Phê duyệt: ${a.kind_label}`, confirmLabel: 'Phê duyệt',
                    message: `${kindMessage(a.kind, a.target)}\nLý do: ${a.reason}`, onConfirm: () => run(() => decideContainment(a.id, 'approve'), 'Đã gửi lệnh tới Agent, đang chờ xác minh…') })}>Phê duyệt</Button>
                  <Button size="sm" variant="ghost" disabled={busy} onClick={() => run(() => decideContainment(a.id, 'reject'))}>Từ chối</Button>
                </>)}
                {a.status === 'PENDING_APPROVAL' && !role.isAdmin && <span style={{ color: '#8b949e' }}>Chờ SOC Admin phê duyệt</span>}
                {a.kind === 'quarantine_file' && a.effect === 'QUARANTINED' && caps.restore_file && role.canRequest && (
                  <Button size="sm" variant="ghost" disabled={busy || !data.agent_online} onClick={() => ask({ title: 'Khôi phục file', needsReason: true,
                    confirmLabel: 'Gửi yêu cầu khôi phục', message: `Đưa ${a.target.path} trở lại vị trí gốc (cần SOC Admin phê duyệt).`,
                    onConfirm: (reason) => run(() => decideContainment(a.id, 'restore', reason), 'Đã tạo yêu cầu khôi phục, chờ phê duyệt') })}>Khôi phục file</Button>)}
              </div>
              {a.error && <div style={{ color: '#fb7185' }}>Lỗi: {a.error.replace(/^[A-Z_]+: /, '')}</div>}
              {a.verification?.processes_still_running?.length > 0 && (
                <div style={{ color: '#fbbf24' }}>File đã cách ly nhưng vẫn còn {a.verification.processes_still_running.length} tiến trình đang chạy từ file này.</div>)}
              <div style={{ color: '#8b949e', fontSize: '0.76rem' }}>
                {a.history.map((h) => `${EVENT[h.event] || h.event} (${h.actor}) ${formatTime(h.at)}`).join(' → ')}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function kindMessage(kind, t) {
  switch (kind) {
    case 'inspect_file': return `Agent đọc metadata, SHA-256, chủ sở hữu và tiến trình đang dùng ${t.path} (chỉ đọc).`;
    case 'quarantine_file': return `Agent chuyển ${t.path} vào kho cách ly của LARP (giữ nguyên nội dung để điều tra, có thể khôi phục). Chỉ thực hiện nếu SHA-256 còn khớp.`;
    case 'terminate_process': return `Agent dừng tiến trình PID ${t.pid} và các tiến trình con, sau khi xác minh lại PID và thời điểm khởi chạy.`;
    case 'collect_process_evidence': return 'Đóng gói bằng chứng hiện có (chuỗi tấn công, tiến trình, kết nối, kết quả kiểm tra file) và lưu mã băm.';
    case 'restore_file': return `Đưa ${t.path} về vị trí gốc.`;
    default: return '';
  }
}
