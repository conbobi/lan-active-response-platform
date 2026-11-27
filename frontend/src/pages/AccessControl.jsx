import { useEffect, useMemo, useState } from 'react';
import { FiShield } from 'react-icons/fi';
import { getAgents } from '../api/agents';
import useAccessControl, { useRole } from '../components/access/useAccessControl';
import BlockList from '../components/access/BlockList';
import { StateBadge } from '../components/access/BlockCard';
import { formatTime } from '../components/access/format';

const FILTERS = [
  ['active', 'Đang hiệu lực / chờ'], ['BLOCKED', 'Đã chặn'], ['UNKNOWN', 'Không xác minh được'],
  ['UNBLOCKED', 'Đã bỏ chặn'], ['', 'Tất cả'],
];

// "Chặn đang hiệu lực": every host IP block from the database, state as last verified by the Agent.
export default function AccessControl() {
  const role = useRole();
  const [agentId, setAgentId] = useState('');
  const [state, setState] = useState('active');
  const [agents, setAgents] = useState([]);
  const [selected, setSelected] = useState(null);
  const params = useMemo(() => ({ ...(agentId ? { agent_id: agentId } : {}), ...(state ? { state } : {}) }), [agentId, state]);
  const { blocks, loading, error, busy, run } = useAccessControl(params);

  useEffect(() => {
    getAgents().then((res) => setAgents(Array.isArray(res) ? res : res?.items || [])).catch(() => setAgents([]));
  }, []);

  const current = blocks.find((b) => b.id === selected);
  return (
    <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        <FiShield className="text-primary" /> Chặn đang hiệu lực
      </h1>
      <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center' }}>
        <select value={agentId} onChange={(e) => setAgentId(e.target.value)}
                style={{ background: '#0d1117', color: '#e6edf3', border: '1px solid #30363d', borderRadius: '0.4rem', padding: '0.4rem' }}>
          <option value="">Tất cả Agent</option>
          {agents.map((a) => <option key={a.id} value={a.id}>{a.hostname || a.id}</option>)}
        </select>
        {FILTERS.map(([value, label]) => (
          <button key={value || 'all'} className="btn btn-ghost btn-sm" onClick={() => setState(value)}
                  style={state === value ? { borderColor: '#58a6ff', color: '#fff' } : undefined}>{label}</button>
        ))}
      </div>
      {error && <div style={{ color: '#fb7185' }}>{error}</div>}
      <div className="card" style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', fontSize: '0.83rem', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ textAlign: 'left', color: '#8b949e' }}>
              {['IP', 'Agent', 'Lý do', 'Incident', 'Bắt đầu lúc', 'Hết hạn', 'Trạng thái', 'Xác minh gần nhất', ''].map((h) => (
                <th key={h} style={{ padding: '0.5rem' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading && <tr><td colSpan={9} style={{ padding: '0.75rem', color: '#8b949e' }}>Đang tải…</td></tr>}
            {!loading && blocks.length === 0 && (
              <tr><td colSpan={9} style={{ padding: '0.75rem', color: '#8b949e' }}>Không có chặn nào khớp bộ lọc.</td></tr>
            )}
            {blocks.map((b) => (
              <tr key={b.id} style={{ borderTop: '1px solid #21262d', color: '#e6edf3', cursor: 'pointer',
                                      background: selected === b.id ? '#161b22' : undefined }}
                  onClick={() => setSelected(selected === b.id ? null : b.id)}>
                <td style={{ padding: '0.5rem', fontFamily: 'monospace' }}>{b.target_ip}</td>
                <td>{b.agent_id}{b.agent_online ? '' : ' (offline)'}</td>
                <td style={{ maxWidth: 260 }}>{b.reason}</td>
                <td>{b.incident_id || '—'}</td>
                <td>{formatTime(b.verified_at)}</td>
                <td>{b.expires_at ? formatTime(b.expires_at) : 'Không'}</td>
                <td><StateBadge block={b} /></td>
                <td>{formatTime(b.verification?.observed_at)}</td>
                <td style={{ color: '#58a6ff' }}>{selected === b.id ? 'Thu gọn' : 'Chi tiết'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {current && <BlockList blocks={[current]} run={run} busy={busy} role={role} incidentOpen={false} />}
    </div>
  );
}
