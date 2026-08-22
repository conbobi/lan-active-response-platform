import React from 'react';
import { FiAlertCircle, FiArrowRight } from 'react-icons/fi';
import Badge from './Badge';

const sevColor = { Critical: 'var(--error)', High: '#f97316', Medium: 'var(--warning)', Low: 'var(--success)' };

export default function RecentAlerts({ events }) {
  const rows = events.slice(0, 6);
  return (
    <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
      <div style={{ padding: '1rem 1.25rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--border)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <FiAlertCircle size={16} color="var(--error)" />
          <h3 style={{ fontWeight: 700, fontSize: '0.95rem' }}>Recent Alerts</h3>
        </div>
        <a href="/alerts" style={{ fontSize: '0.8rem', color: 'var(--primary)', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
          View all <FiArrowRight size={12} />
        </a>
      </div>
      {rows.map((e) => (
        <div key={e.id} style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '0.75rem 1.25rem', borderBottom: '1px solid var(--border)', transition: 'background 0.2s', cursor: 'pointer' }}
          onMouseEnter={(el) => (el.currentTarget.style.background = 'var(--primary-light)')}
          onMouseLeave={(el) => (el.currentTarget.style.background = 'transparent')}
        >
          <div style={{ width: 8, height: 8, borderRadius: '50%', background: sevColor[e.severity] || 'var(--info)', flexShrink: 0 }} />
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: '0.85rem', fontWeight: 500, color: 'var(--text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{e.type.replace('_', ' ')}</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)' }}>{e.sourceIp}</div>
          </div>
          <Badge status={e.severity.toLowerCase()} label={e.severity} showDot={false} />
          <span style={{ fontSize: '0.72rem', color: 'var(--text-tertiary)', flexShrink: 0 }}>{new Date(e.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
        </div>
      ))}
    </div>
  );
}
