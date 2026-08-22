import React from 'react';
import { FiCpu, FiAlertCircle, FiShield, FiSlash, FiTrendingUp, FiTrendingDown } from 'react-icons/fi';

const configs = {
  agents: { icon: <FiCpu size={20} />, label: 'Agents Online', color: 'var(--primary)' },
  alerts: { icon: <FiAlertCircle size={20} />, label: 'Alerts Today', color: 'var(--error)' },
  risk: { icon: <FiShield size={20} />, label: 'Avg Risk Score', color: 'var(--warning)' },
  blocked: { icon: <FiSlash size={20} />, label: 'IPs Blocked', color: 'var(--success)' },
};

export default function KpiCard({ type, value, trend, trendValue }) {
  const cfg = configs[type] || { icon: null, label: type, color: 'var(--primary)' };
  const isUp = trendValue > 0;
  return (
    <div className="kpi-card">
      <div className="kpi-icon-wrap" style={{ background: `${cfg.color}18`, color: cfg.color }}>
        {cfg.icon}
      </div>
      <div className="kpi-label">{cfg.label}</div>
      <div className="kpi-value">{value}</div>
      {trendValue != null && (
        <div className={`kpi-trend ${isUp ? 'up' : 'down'}`}>
          {isUp ? <FiTrendingUp size={13} /> : <FiTrendingDown size={13} />}
          <span>{Math.abs(trendValue)}% vs yesterday</span>
        </div>
      )}
    </div>
  );
}