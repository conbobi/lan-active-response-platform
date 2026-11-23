import React from 'react';

export default function HealthScoreGauge({ summary, activityVerified }) {
  const counts = summary.health_counts;
  const activity = activityVerified ? summary.active_incidents : 0;

  return (
    <section className="card" style={{ marginBottom: '1.25rem' }}>
      <h3>Endpoint observation</h3>
      <p>Snapshot {new Date(summary.as_of).toLocaleString()}</p>
      <p>
        {counts.online || 0} online · {counts.stale || 0} stale · {counts.offline || 0} offline
        {' · '}{counts.decommissioned || 0} decommissioned
      </p>
      <p>{activity} verified active {activity === 1 ? 'behavior' : 'behaviors'} · {summary.incident_queue} incidents awaiting SOC review</p>
    </section>
  );
}
