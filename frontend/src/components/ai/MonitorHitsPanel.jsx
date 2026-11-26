import { useEffect, useState } from 'react';
import api from '../../api/api';

// Matches recorded while a rule runs in monitoring mode (no incidents), plus whether it may be promoted.
export default function MonitorHitsPanel({ ruleId, refreshKey }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    let alive = true;
    api.get(`/rules/${ruleId}/monitor-hits?limit=50`)
      .then((res) => alive && (setData(res), setError(null)))
      .catch((err) => alive && setError(err.message));
    return () => { alive = false; };
  }, [ruleId, refreshKey]);

  if (error) return <div style={{ color: '#f87171', fontSize: '0.85rem' }}>Không tải được lần khớp: {error}</div>;
  if (!data) return null;
  const gate = data.promotion || {};
  return (
    <div style={{ border: '1px solid rgba(251, 191, 36, 0.3)', borderRadius: '0.5rem', padding: '1rem',
                  background: 'rgba(251, 191, 36, 0.05)' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem' }}>
        <strong style={{ color: '#fcd34d' }}>Giám sát trên telemetry thật: {data.total} lần khớp</strong>
        <span style={{ fontSize: '0.8rem', color: gate.allowed ? '#34d399' : '#fca5a5' }}>
          {gate.allowed ? 'Có thể bật chính thức' : 'Chưa thể bật chính thức'}: {gate.reason}
        </span>
      </div>
      <div style={{ fontSize: '0.75rem', color: '#9ca3af', margin: '0.35rem 0 0.75rem' }}>
        Ở chế độ giám sát, rule chạy trên dữ liệu Agent gửi về và chỉ ghi nhận lần khớp, không tạo incident.
      </div>
      {data.items.length === 0 ? (
        <div style={{ fontSize: '0.85rem', color: '#9ca3af' }}>Chưa có lần khớp nào.</div>
      ) : (
        <table style={{ width: '100%', fontSize: '0.78rem', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ color: '#9ca3af', textAlign: 'left' }}>
              <th style={{ padding: '0.3rem' }}>Thời điểm</th><th>Agent</th><th>PID</th>
              <th>Command line</th><th>Tiến trình cha</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((hit) => (
              <tr key={hit.evidence_id} style={{ borderTop: '1px solid #1f2937', color: '#e5e7eb' }}>
                <td style={{ padding: '0.3rem', whiteSpace: 'nowrap' }}>{hit.observed_at?.replace('T', ' ').slice(0, 19)}</td>
                <td>{hit.agent_id}</td>
                <td>{hit.process?.pid}</td>
                <td style={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>{hit.process?.cmdline}</td>
                <td style={{ fontFamily: 'monospace', wordBreak: 'break-all', color: '#9ca3af' }}>
                  {hit.process?.parent?.cmdline || '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
