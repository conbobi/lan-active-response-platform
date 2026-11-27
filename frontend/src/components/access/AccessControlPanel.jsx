import { useEffect, useState } from 'react';
import { FiShield } from 'react-icons/fi';
import Button from '../ui/Button';
import * as ac from '../../api/accessControl';
import useAccessControl, { useRole } from './useAccessControl';
import BlockList from './BlockList';
import { BlockDialog } from './AccessDialogs';

// "Kiểm soát truy cập" inside Incident Detail: evidence-based IP suggestions and the blocks of this incident.
export default function AccessControlPanel({ incident }) {
  const role = useRole();
  const { blocks, loading, error, busy, run } = useAccessControl({ incident_id: incident.id });
  const [suggestions, setSuggestions] = useState([]);
  const [target, setTarget] = useState(null);

  useEffect(() => {
    ac.getSuggestions(incident.id).then((res) => setSuggestions(res.items || [])).catch(() => setSuggestions([]));
  }, [incident.id]);

  const blockedIps = new Set(blocks.filter((b) => !['REJECTED'].includes(b.status) && b.effective_state !== 'UNBLOCKED'
    && !(b.status === 'FAILED' && b.effective_state === 'NOT_BLOCKED')).map((b) => b.target_ip));
  const open = !['resolved', 'closed', 'false_positive'].includes(String(incident.status || '').toLowerCase());

  return (
    <div style={{ border: '1px solid #30363d', borderRadius: '0.75rem', padding: '1rem', marginBottom: '1rem',
                  background: '#161b22' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
        <FiShield color="#60a5fa" />
        <strong style={{ color: '#e6edf3' }}>Kiểm soát truy cập · {incident.agent_id}</strong>
      </div>
      {error && <div style={{ color: '#fb7185', fontSize: '0.85rem', marginBottom: '0.5rem' }}>{error}</div>}
      {loading ? <div style={{ color: '#8b949e', fontSize: '0.85rem' }}>Đang tải trạng thái chặn…</div> : (
        <>
          {suggestions.filter((s) => !blockedIps.has(s.ip)).map((s) => (
            <div key={s.ip} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.75rem',
                                     border: '1px dashed #30363d', borderRadius: '0.5rem', padding: '0.6rem 0.8rem',
                                     marginBottom: '0.6rem' }}>
              <div style={{ fontSize: '0.82rem' }}>
                <div style={{ fontFamily: 'monospace', color: '#fff' }}>{s.ip}</div>
                <div style={{ color: '#8b949e' }}>Đề xuất theo bằng chứng: {s.basis.join('; ')}</div>
                {!s.allowed && <div style={{ color: '#fbbf24' }}>Không thể chặn: {s.protected_reason}</div>}
              </div>
              {s.allowed && role.canRequest && <Button size="sm" onClick={() => setTarget(s)}>Chặn IP</Button>}
            </div>
          ))}
          {blocks.length === 0 && suggestions.length === 0 && (
            <div style={{ color: '#8b949e', fontSize: '0.85rem' }}>Chưa có IP nào được xác định để chặn cho incident này.</div>
          )}
          <BlockList blocks={blocks} run={run} busy={busy} role={role} incidentOpen={open} />
        </>
      )}
      <BlockDialog open={!!target} target={target} agentId={incident.agent_id} incidentId={incident.id}
                   onClose={() => setTarget(null)}
                   onConfirm={async (reason) => {
                     const t = target;
                     setTarget(null);
                     await run(t.ip, () => ac.requestBlock({ agent_id: incident.agent_id, target_ip: t.ip,
                                                             incident_id: incident.id, reason }),
                               'Đã tạo yêu cầu chặn, chờ SOC Admin phê duyệt');
                   }} />
    </div>
  );
}
