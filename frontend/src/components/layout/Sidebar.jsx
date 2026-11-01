// src/components/layout/Sidebar.jsx
import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  FiGrid,
  FiAlertOctagon,
  FiSearch,
  FiClock,
  FiShield,
  FiCpu,
  FiSliders,
  FiSettings,
} from 'react-icons/fi';

const operationsNav = [
  { to: '/', icon: <FiGrid size={16} />, label: 'Dashboard', end: true },
  { to: '/incidents', icon: <FiAlertOctagon size={16} />, label: 'Incidents' },
  { to: '/investigate', icon: <FiSearch size={16} />, label: 'Investigate' },
];

const responseNav = [
  { to: '/actions', icon: <FiClock size={16} />, label: 'Actions History' },
  { to: '/policies', icon: <FiShield size={16} />, label: 'Response Policies' },
];

const managementNav = [
  { to: '/agents', icon: <FiCpu size={16} />, label: 'Endpoints' },
  { to: '/detection', icon: <FiSliders size={16} />, label: 'Detection Studio' },
  { to: '/settings', icon: <FiSettings size={16} />, label: 'Settings' },
];

export default function Sidebar() {
  return (
    <nav className="sidebar">
      {/* 1. OPERATIONS (Tier 1 — 80% time) */}
      <div className="sidebar-section-label">Operations</div>
      {operationsNav.map(({ to, icon, label, end }) => (
        <NavLink key={to} to={to} end={end}>
          {icon}
          {label}
        </NavLink>
      ))}

      {/* 2. RESPONSE (Tier 2) */}
      <div className="sidebar-section-label" style={{ marginTop: '1rem' }}>Response</div>
      {responseNav.map(({ to, icon, label }) => (
        <NavLink key={to} to={to}>
          {icon}
          {label}
        </NavLink>
      ))}

      {/* 3. MANAGEMENT & CONFIG (Tier 3 & Admin) */}
      <div className="sidebar-section-label" style={{ marginTop: '1rem' }}>Management</div>
      {managementNav.map(({ to, icon, label }) => (
        <NavLink key={to} to={to}>
          {icon}
          {label}
        </NavLink>
      ))}

      {/* Sidebar Footer */}
      <div className="sidebar-footer" style={{ marginTop: 'auto', paddingTop: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          <FiSliders size={14} color="var(--text-tertiary)" />
          <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>LARP Blue Team SOC v2.0</span>
        </div>
      </div>
    </nav>
  );
}