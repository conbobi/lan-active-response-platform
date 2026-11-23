import React from 'react';
import { FiServer, FiCheckCircle, FiAlertCircle, FiClock, FiShield } from 'react-icons/fi';

export default function HealthScoreGauge({ summary, activityVerified }) {
  if (!summary) return null;

  const counts = summary.health_counts || {};
  const online = counts.online || 0;
  const stale = counts.stale || 0;
  const offline = counts.offline || 0;
  const decommissioned = counts.decommissioned || 0;
  const total = summary.total_agents || (online + stale + offline + decommissioned) || 1;

  const onlinePct = Math.round((online / total) * 100);
  const stalePct = Math.round((stale / total) * 100);
  const offlinePct = Math.round((offline / total) * 100);

  const activeIncidents = activityVerified ? (summary.active_incidents || 0) : 0;
  const queueCount = summary.incident_queue || 0;
  const asOfTime = summary.as_of ? new Date(summary.as_of).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—';

  return (
    <section className="card" style={{
      padding: '0.875rem 1.25rem',
      marginBottom: '1.25rem',
      background: 'var(--bg-secondary)',
      border: '1px solid var(--border-primary)',
      borderRadius: 'var(--radius-md, 10px)',
    }}>
      {/* Top Header Row */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.65rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <FiServer size={15} color="var(--primary)" />
          <span style={{ fontWeight: 700, fontSize: '0.875rem', color: 'var(--text-primary)', letterSpacing: '0.01em' }}>
            Endpoint Fleet Observation
          </span>
          <span style={{
            fontSize: '0.7rem',
            color: 'var(--text-tertiary)',
            background: 'var(--bg-tertiary)',
            padding: '0.15rem 0.45rem',
            borderRadius: '4px',
            border: '1px solid var(--border-subtle)',
          }}>
            Snapshot: {asOfTime}
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', fontSize: '0.75rem' }}>
          {activeIncidents > 0 ? (
            <span style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.35rem',
              color: 'var(--error)',
              fontWeight: 600,
              background: 'var(--error-dim)',
              padding: '0.15rem 0.5rem',
              borderRadius: '9999px',
            }}>
              <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--error)' }} />
              {activeIncidents} Active Threat{activeIncidents > 1 ? 's' : ''}
            </span>
          ) : (
            <span style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.35rem',
              color: 'var(--success)',
              fontWeight: 600,
              background: 'var(--success-dim)',
              padding: '0.15rem 0.5rem',
              borderRadius: '9999px',
            }}>
              <FiCheckCircle size={12} /> Fleet Normal
            </span>
          )}

          <span style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.3rem',
            color: queueCount > 0 ? 'var(--warning)' : 'var(--text-tertiary)',
            fontWeight: 500,
          }}>
            <FiShield size={12} />
            {queueCount} in SOC queue
          </span>
        </div>
      </div>

      {/* Segmented Progress Bar */}
      <div style={{
        height: '6px',
        width: '100%',
        background: 'rgba(51, 65, 85, 0.4)',
        borderRadius: '9999px',
        overflow: 'hidden',
        display: 'flex',
        marginBottom: '0.75rem',
      }} title={`Online: ${onlinePct}% · Stale: ${stalePct}% · Offline: ${offlinePct}%`}>
        <div style={{ width: `${onlinePct}%`, background: 'var(--success, #10b981)', transition: 'width 0.3s' }} />
        <div style={{ width: `${stalePct}%`, background: 'var(--warning, #f59e0b)', transition: 'width 0.3s' }} />
        <div style={{ width: `${offlinePct}%`, background: 'var(--text-disabled, #64748b)', transition: 'width 0.3s' }} />
      </div>

      {/* Status Chips Row */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
        {/* Online Chip */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', fontSize: '0.75rem' }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--success, #10b981)' }} />
          <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{online}</span>
          <span style={{ color: 'var(--text-secondary)' }}>Online ({onlinePct}%)</span>
        </div>

        {/* Stale Chip */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', fontSize: '0.75rem' }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--warning, #f59e0b)' }} />
          <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{stale}</span>
          <span style={{ color: 'var(--text-secondary)' }}>Stale</span>
        </div>

        {/* Offline Chip */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', fontSize: '0.75rem' }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#64748b' }} />
          <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{offline}</span>
          <span style={{ color: 'var(--text-secondary)' }}>Offline</span>
        </div>

        {decommissioned > 0 && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', fontSize: '0.75rem' }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#475569' }} />
            <span style={{ fontWeight: 600, color: 'var(--text-tertiary)' }}>{decommissioned}</span>
            <span style={{ color: 'var(--text-tertiary)' }}>Decommissioned</span>
          </div>
        )}
      </div>
    </section>
  );
}
