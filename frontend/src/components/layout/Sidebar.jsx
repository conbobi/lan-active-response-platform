import React from 'react';
import { NavLink } from 'react-router-dom';
import { FiGrid, FiCpu, FiAlertCircle, FiGlobe, FiZap, FiSettings, FiShield, FiSliders, FiAlertOctagon, FiTerminal } from 'react-icons/fi';

const navItems = [
  { to: '/', icon: <FiGrid size={17} />, label: 'Dashboard', end: true },
  { to: '/agents', icon: <FiCpu size={17} />, label: 'Agents' },
  { to: '/alerts', icon: <FiAlertCircle size={17} />, label: 'Alerts' },
  { to: '/network', icon: <FiGlobe size={17} />, label: 'Network' },
  { to: '/incidents', icon: <FiAlertOctagon size={17} />, label: 'Incidents' },
  { to: '/commands', icon: <FiTerminal size={17} />, label: 'Commands' },
  { to: '/rules', icon: <FiShield size={17} />, label: 'Rules Engine' },
  { to: '/attack', icon: <FiZap size={17} />, label: 'Attack Sim' },
  { to: '/settings', icon: <FiSettings size={17} />, label: 'Settings' },
];

export default function Sidebar() {
  return (
    <nav className="sidebar">
      <div className="sidebar-section-label">Navigation</div>
      {navItems.map(({ to, icon, label, end }) => (
        <NavLink key={to} to={to} end={end}>
          {icon}
          {label}
        </NavLink>
      ))}
      <div className="sidebar-footer">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          <FiSliders size={15} color="#4a5568" />
          <span style={{ fontSize: '0.75rem', color: '#4a5568' }}>v1.0.0 — SOC Dashboard</span>
        </div>
      </div>
    </nav>
  );
}