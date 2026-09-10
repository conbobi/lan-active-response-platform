import React from 'react';

const variantMap = {
  online: 'badge-online',
  active: 'badge-online',
  offline: 'badge-offline',
  dead: 'badge-offline',
  inactive: 'badge-offline',
  isolated: 'badge-warning',
  quarantine: 'badge-critical',
  warning: 'badge-warning',
  critical: 'badge-critical',
  info: 'badge-info',
  low: 'badge-low',
  medium: 'badge-medium',
  high: 'badge-high',
};

const labelMap = {
  online: 'Online',
  active: 'Online',
  offline: 'Offline',
  dead: 'Offline',
  inactive: 'Inactive',
  isolated: 'Isolated',
  quarantine: 'Quarantine',
  warning: 'Warning',
  critical: 'Critical',
  info: 'Info',
  low: 'Low',
  medium: 'Medium',
  high: 'High',
};

export default function Badge({ status, label, showDot = true }) {
  const key = (status || '').toLowerCase();
  const cls = variantMap[key] || 'badge-info';
  const text = label || labelMap[key] || status;
  return (
    <span className={`badge ${cls}`}>
      {showDot && <span className="badge-dot" />}
      {text}
    </span>
  );
}
