import React from 'react';

const variantMap = {
  online: 'badge-online',
  offline: 'badge-offline',
  warning: 'badge-warning',
  critical: 'badge-critical',
  info: 'badge-info',
  low: 'badge-low',
  medium: 'badge-medium',
  high: 'badge-high',
};

const labelMap = {
  online: 'Online', offline: 'Offline', warning: 'Warning',
  critical: 'Critical', info: 'Info', low: 'Low', medium: 'Medium', high: 'High',
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
