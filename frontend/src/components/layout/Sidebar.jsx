// src/components/layout/Sidebar.jsx
import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  FiGrid,
  FiCpu,
  FiAlertCircle,
  FiGlobe,
  FiZap,
  FiSettings,
  FiShield,
  FiSliders,
  FiAlertOctagon,
  FiTerminal,
  FiActivity,
  FiSearch,
  FiFileText,
  FiCheckSquare,
  FiBell,
} from 'react-icons/fi';

const mainNavItems = [
  { to: '/', icon: <FiGrid size={16} />, label: 'Dashboard', end: true },
  { to: '/agents', icon: <FiCpu size={16} />, label: 'Agents' },
  { to: '/alerts', icon: <FiAlertCircle size={16} />, label: 'Alerts' },
  { to: '/network', icon: <FiGlobe size={16} />, label: 'Network 3D' },
  { to: '/incidents', icon: <FiAlertOctagon size={16} />, label: 'Incidents' },
  { to: '/commands', icon: <FiTerminal size={16} />, label: 'Commands Audit' },
];

const intelligenceNavItems = [
  { to: '/risk', icon: <FiActivity size={16} />, label: 'Risk Monitor' },
  { to: '/rules/detection', icon: <FiShield size={16} />, label: 'Detection Rules' },
  { to: '/threat-intel', icon: <FiSearch size={16} />, label: 'Threat Intel' },
  { to: '/process', icon: <FiCpu size={16} />, label: 'Process Root Cause' },
];

const adminNavItems = [
  { to: '/reports', icon: <FiFileText size={16} />, label: 'Reports' },
  { to: '/whitelist', icon: <FiCheckSquare size={16} />, label: 'Whitelist' },
  { to: '/notifications', icon: <FiBell size={16} />, label: 'Notifications' },
  { to: '/rules', icon: <FiSliders size={16} />, label: 'Rules Engine' },
  { to: '/attack', icon: <FiZap size={16} />, label: 'Attack Sim' },
  { to: '/settings', icon: <FiSettings size={16} />, label: 'Settings' },
];

export default function Sidebar() {
  return (
    <nav className="sidebar">
      <div className="sidebar-section-label">SOC Monitoring</div>
      {mainNavItems.map(({ to, icon, label, end }) => (
        <NavLink key={to} to={to} end={end}>
          {icon}
          {label}
        </NavLink>
      ))}

      <div className="sidebar-section-label" style={{ marginTop: '1rem' }}>Cyber Intelligence</div>
      {intelligenceNavItems.map(({ to, icon, label }) => (
        <NavLink key={to} to={to}>
          {icon}
          {label}
        </NavLink>
      ))}

      <div className="sidebar-section-label" style={{ marginTop: '1rem' }}>Admin & Response</div>
      {adminNavItems.map(({ to, icon, label }) => (
        <NavLink key={to} to={to}>
          {icon}
          {label}
        </NavLink>
      ))}

      <div className="sidebar-footer" style={{ marginTop: 'auto', paddingTop: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          <FiSliders size={14} color="#64748b" />
          <span style={{ fontSize: '0.75rem', color: '#64748b' }}>LARP SOC Platform v2.0</span>
        </div>
      </div>
    </nav>
  );
}