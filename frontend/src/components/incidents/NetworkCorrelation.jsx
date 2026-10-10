// src/components/incidents/NetworkCorrelation.jsx
import React from 'react';
import Button from '../ui/Button';
import {
  FiGlobe,
  FiLock,
  FiShield,
  FiCheckCircle,
  FiAlertTriangle,
  FiActivity,
  FiArrowUpRight
} from 'react-icons/fi';

export default function NetworkCorrelation({
  incident,
  onAction,
  actionLoading,
}) {
  const networkIndicators = incident?.networkIndicators || [];
  const culprit = incident?.culpritProcess || { name: 'key_test.exe', pid: 4128 };

  // Fallback demo indicator if empty and incident mentions C2/network
  const displayIndicators = networkIndicators.length > 0 ? networkIndicators : (
    incident?.description && (incident.description.includes('4444') || incident.description.includes('c2') || incident.description.includes('network')) ? [
      {
        dst_ip: '192.168.10.55',
        dst_port: 4444,
        protocol: 'TCP',
        bytes_sent: 1024,
        packets_sent: 12,
        process_name: culprit.name || 'key_test.exe',
      }
    ] : []
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Header */}
      <div>
        <h4 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
          Process ↔ Network Socket Correlation
        </h4>
        <span style={{ fontSize: '0.8rem', color: 'var(--text-tertiary)' }}>
          Trace outbound connections, beaconing intervals, and C2 infrastructure linked to host processes
        </span>
      </div>

      {/* Network Connections Table */}
      {displayIndicators.length === 0 ? (
        <div
          style={{
            textAlign: 'center',
            padding: '2.5rem',
            background: 'var(--bg-secondary)',
            borderRadius: 'var(--radius-md)',
            border: '1px solid var(--border)',
            color: 'var(--text-tertiary)',
          }}
        >
          <FiCheckCircle size={32} style={{ margin: '0 auto 0.5rem', color: 'var(--success)' }} />
          <p style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>Không có kết nối mạng bất thường</p>
          <span style={{ fontSize: '0.8rem' }}>Agent chưa ghi nhận luồng truyền tải dữ liệu hoặc beacon ra ngoài C2 IP.</span>
        </div>
      ) : (
        <div
          style={{
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius-md)',
            overflow: 'hidden',
          }}
        >
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
            <thead>
              <tr style={{ background: 'rgba(255, 255, 255, 0.02)', borderBottom: '1px solid var(--border)', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontSize: '0.72rem', letterSpacing: '0.05em' }}>
                <th style={{ padding: '0.75rem 1rem' }}>Associated Process</th>
                <th style={{ padding: '0.75rem 1rem' }}>Destination IP</th>
                <th style={{ padding: '0.75rem 1rem' }}>Dest Port</th>
                <th style={{ padding: '0.75rem 1rem' }}>Protocol</th>
                <th style={{ padding: '0.75rem 1rem' }}>Traffic Sent</th>
                <th style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>Mitigation</th>
              </tr>
            </thead>
            <tbody>
              {displayIndicators.map((item, index) => {
                const isCulprit = item.process_name === culprit.name || (item.dst_port === 4444);
                return (
                  <tr
                    key={index}
                    style={{
                      borderBottom: '1px solid var(--border)',
                      background: isCulprit ? 'rgba(239, 68, 68, 0.06)' : 'transparent',
                    }}
                  >
                    <td style={{ padding: '0.75rem 1rem' }}>
                      <span
                        style={{
                          fontWeight: 700,
                          color: isCulprit ? 'var(--error)' : 'var(--text-primary)',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '0.4rem',
                        }}
                      >
                        <FiArrowUpRight size={14} />
                        {item.process_name || culprit.name}
                      </span>
                    </td>
                    <td style={{ padding: '0.75rem 1rem' }}>
                      <code style={{ color: isCulprit ? 'var(--warning)' : 'var(--text-primary)', fontWeight: 600 }}>
                        {item.dst_ip}
                      </code>
                    </td>
                    <td style={{ padding: '0.75rem 1rem' }}>
                      <span
                        style={{
                          padding: '0.15rem 0.45rem',
                          borderRadius: 'var(--radius-xs)',
                          fontSize: '0.78rem',
                          fontWeight: 700,
                          background: isCulprit ? 'rgba(239, 68, 68, 0.2)' : 'var(--bg-tertiary)',
                          color: isCulprit ? 'var(--error)' : 'var(--text-secondary)',
                        }}
                      >
                        {item.dst_port}
                      </span>
                    </td>
                    <td style={{ padding: '0.75rem 1rem', color: 'var(--text-secondary)' }}>
                      {item.protocol || 'TCP'}
                    </td>
                    <td style={{ padding: '0.75rem 1rem', color: 'var(--text-secondary)' }}>
                      {item.bytes_sent != null ? `${item.bytes_sent} B` : 'Active Socket'}
                    </td>
                    <td style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={actionLoading}
                        iconLeft={<FiLock size={12} />}
                        onClick={() => onAction && onAction('block_ip', { ip: item.dst_ip })}
                      >
                        Block IP
                      </Button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Threat Intel C2 Correlation Card */}
      <div
        style={{
          background: 'var(--bg-secondary)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius-md)',
          padding: '1rem 1.25rem',
        }}
      >
        <h5 style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-tertiary)', textTransform: 'uppercase', marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
          <FiShield size={14} color="var(--primary)" />
          Threat Intelligence Reputation Match
        </h5>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '0.75rem', fontSize: '0.82rem' }}>
          <div style={{ background: 'var(--bg-tertiary)', padding: '0.75rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
            <span style={{ color: 'var(--text-tertiary)', display: 'block', marginBottom: '0.2rem' }}>Target Port Reputation</span>
            <strong style={{ color: 'var(--error)' }}>Port 4444 / Metasploit Default C2</strong>
            <p style={{ margin: '0.2rem 0 0', color: 'var(--text-secondary)', fontSize: '0.78rem' }}>
              Common default reverse shell handler port. Kích hoạt rule C2 Communication (+30 pts).
            </p>
          </div>

          <div style={{ background: 'var(--bg-tertiary)', padding: '0.75rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
            <span style={{ color: 'var(--text-tertiary)', display: 'block', marginBottom: '0.2rem' }}>Traffic Signature</span>
            <strong style={{ color: 'var(--warning)' }}>Beaconing Heartbeat Pattern</strong>
            <p style={{ margin: '0.2rem 0 0', color: 'var(--text-secondary)', fontSize: '0.78rem' }}>
              Chu kỳ phát sinh kết nối định kỳ dưới 15 giây, phù hợp với hành vi keylogger exfiltration.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
