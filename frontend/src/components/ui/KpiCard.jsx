import React from 'react';
import { FiCpu, FiAlertCircle, FiShield, FiSlash, FiTrendingUp, FiTrendingDown } from 'react-icons/fi';

const configs = {
  agents: { icon: <FiCpu size={20} />, label: 'Agents Online', color: 'var(--primary)' },
  alerts: { icon: <FiAlertCircle size={20} />, label: 'Alerts Today', color: 'var(--error)' },
  risk: { icon: <FiShield size={20} />, label: 'Avg Risk Score', color: 'var(--warning)' },
  blocked: { icon: <FiSlash size={20} />, label: 'IPs Blocked', color: 'var(--success)' },
};

export default function KpiCard({
  type,
  title,
  label,
  subtitle,
  icon,
  color,
  value,
  trend,
  trendValue,
}) {
  const cfg = (type && configs[type]) || {
    icon: icon || null,
    label: title || label || type,
    color: color ? (color.startsWith('var(') ? color : `var(--${color}, var(--primary))`) : 'var(--primary)',
  };

  const cardIcon = icon || cfg.icon;
  const cardLabel = title || label || cfg.label;
  const cardColor = color
    ? color.startsWith('var(') || color.startsWith('#') || color.startsWith('rgb')
      ? color
      : `var(--${color}, var(--primary))`
    : cfg.color;

  const isUp = trendValue > 0;

  return (
    <div className="kpi-card">
      <div className="kpi-icon-wrap" style={{ background: `${cardColor}18`, color: cardColor }}>
        {cardIcon}
      </div>
      <div className="kpi-label">{cardLabel}</div>
      <div className="kpi-value">{value}</div>
      {subtitle && (
        <div style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', marginTop: '0.2rem' }}>
          {subtitle}
        </div>
      )}
      {trendValue != null && (
        <div className={`kpi-trend ${isUp ? 'up' : 'down'}`}>
          {isUp ? <FiTrendingUp size={13} /> : <FiTrendingDown size={13} />}
          <span>{Math.abs(trendValue)}% vs yesterday</span>
        </div>
      )}
    </div>
  );
}