// src/components/layout/Sidebar.jsx
import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  FiGrid,
  FiCpu,
  FiUsers,
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
  FiGitBranch,
  FiClock,
} from 'react-icons/fi';

const socMonitoringNav = [
  { to: '/', icon: <FiGrid size={16} />, label: 'Dashboard', end: true },
  { to: '/risk', icon: <FiActivity size={16} />, label: 'Risk Monitor' },
  { to: '/alerts', icon: <FiAlertCircle size={16} />, label: 'Alerts' },
];

const endpointsNav = [
  { to: '/agents', icon: <FiCpu size={16} />, label: 'Agents' },
  { to: '/groups', icon: <FiUsers size={16} />, label: 'Agent Groups' },
];

const detectionNav = [
  { to: '/rules/detection', icon: <FiShield size={16} />, label: 'Detection Rules' },
  { to: '/rules/process-chains', icon: <FiGitBranch size={16} />, label: 'Process Chains' },
  { to: '/rules/yara', icon: <FiShield size={16} />, label: 'YARA Signatures' },
  { to: '/process', icon: <FiCpu size={16} />, label: 'Process Root Cause' },
];

const responseNav = [
  { to: '/incidents', icon: <FiAlertOctagon size={16} />, label: 'Incidents' },
  { to: '/actions', icon: <FiClock size={16} />, label: 'Actions History' },
  { to: '/policies', icon: <FiShield size={16} />, label: 'Response Policies' },
  { to: '/commands', icon: <FiTerminal size={16} />, label: 'Commands Audit' },
];

const networkNav = [
  { to: '/network', icon: <FiGlobe size={16} />, label: 'Network 3D' },
];

const adminNav = [
  { to: '/settings', icon: <FiSettings size={16} />, label: 'Settings' },
  { to: '/threat-intel', icon: <FiSearch size={16} />, label: 'Threat Intel' },
  { to: '/whitelist', icon: <FiCheckSquare size={16} />, label: 'Whitelist' },
  { to: '/notifications', icon: <FiBell size={16} />, label: 'Notifications' },
  { to: '/reports', icon: <FiFileText size={16} />, label: 'Reports' },
  { to: '/attack', icon: <FiZap size={16} />, label: 'Attack Sim' },
];

export default function Sidebar() {
  return (
    <nav className="sidebar">
      {/* 1. SOC Monitoring */}
      <div className="sidebar-section-label">SOC Monitoring</div>
      {socMonitoringNav.map(({ to, icon, label, end }) => (
        <NavLink key={to} to={to} end={end}>
          {icon}
          {label}
        </NavLink>
      ))}

      {/* 2. Endpoints */}
      <div className="sidebar-section-label" style={{ marginTop: '0.85rem' }}>Endpoints</div>
      {endpointsNav.map(({ to, icon, label }) => (
        <NavLink key={to} to={to}>
          {icon}
          {label}
        </NavLink>
      ))}

      {/* 3. Detection */}
      <div className="sidebar-section-label" style={{ marginTop: '0.85rem' }}>Detection</div>
      {detectionNav.map(({ to, icon, label }) => (
        <NavLink key={to} to={to}>
          {icon}
          {label}
        </NavLink>
      ))}

      {/* 4. Response & Remediation */}
      <div className="sidebar-section-label" style={{ marginTop: '0.85rem' }}>Response & Remediation</div>
      {responseNav.map(({ to, icon, label }) => (
        <NavLink key={to} to={to}>
          {icon}
          {label}
        </NavLink>
      ))}

      {/* 5. Network */}
      <div className="sidebar-section-label" style={{ marginTop: '0.85rem' }}>Network</div>
      {networkNav.map(({ to, icon, label }) => (
        <NavLink key={to} to={to}>
          {icon}
          {label}
        </NavLink>
      ))}

      {/* 6. System & Admin */}
      <div className="sidebar-section-label" style={{ marginTop: '0.85rem' }}>System & Admin</div>
      {adminNav.map(({ to, icon, label }) => (
        <NavLink key={to} to={to}>
          {icon}
          {label}
        </NavLink>
      ))}

      {/* Sidebar Footer */}
      <div className="sidebar-footer" style={{ marginTop: 'auto', paddingTop: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          <FiSliders size={14} color="#64748b" />
          <span style={{ fontSize: '0.75rem', color: '#64748b' }}>LARP SOC Platform v2.0</span>
        </div>
      </div>
    </nav>
  );
}