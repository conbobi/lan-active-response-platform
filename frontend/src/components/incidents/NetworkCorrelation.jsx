import React from 'react';
import { Link } from 'react-router-dom';

function endpoint(ip, port) {
  if (!ip) return '—';
  return `${ip.includes(':') ? `[${ip}]` : ip}${port ? `:${port}` : ''}`;
}

export default function NetworkCorrelation({ incident }) {
  const rows = incident?.networkIndicators || [];
  const evidence = incident?.detection_evidence;
  const agentId = incident?.agentId || incident?.agent_id;
  if (!rows.length) return <p>Incident chưa có bằng chứng socket.</p>;

  return (
    <div style={{ display: 'grid', gap: '1rem' }}>
      {evidence?.classification && (
        <div>
          <strong>{evidence.classification}</strong>
          <p>Risk Score {incident.riskScore}/100 · Confidence {Math.round(evidence.confidence * 100)}% · {evidence.observations} lượt quan sát</p>
        </div>
      )}
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', textAlign: 'left' }}>
          <thead>
            <tr><th>Process / PID</th><th>Local</th><th>Remote</th><th>Socket</th></tr>
          </thead>
          <tbody>
            {rows.map((row, index) => {
              const holders = row.holders?.length ? row.holders : (row.pid ? [{
                pid: row.pid, name: row.process_name, process_start_time: row.process_start_time,
              }] : []);
              return (
                <tr key={row.socket_id || index}>
                  <td>
                    {holders.length ? holders.map((holder) => {
                      const label = `${holder.name || 'unknown'} (PID ${holder.pid})`;
                      return <div key={holder.pid}>
                        {agentId && holder.process_start_time ? (
                          <Link to={`/investigate?tab=process&agent=${encodeURIComponent(agentId)}&pid=${holder.pid}&started=${holder.process_start_time}`}>
                            {label}
                          </Link>
                        ) : label}
                        {holder.stdio_fds?.length > 0 && <small> · stdio {holder.stdio_fds.join(', ')}</small>}
                      </div>;
                    }) : <span>Unknown{row.attribution && ` · ${row.attribution}`}</span>}
                  </td>
                  <td><code>{endpoint(row.src_ip, row.src_port)}</code></td>
                  <td>
                    <code>{endpoint(row.dst_ip, row.dst_port)}</code>
                    {row.overlay && <div>{row.overlay}</div>}
                    {row.category === 'shared_cgnat' && <div>Shared / CGNAT</div>}
                  </td>
                  <td>{[row.protocol, row.status, row.direction].filter(Boolean).join(' · ')}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {evidence?.signals?.length > 0 && (
        <ul>{evidence.signals.map((signal) => <li key={signal.reason}>{signal.reason} (+{signal.score})</li>)}</ul>
      )}
    </div>
  );
}
