import React from 'react';
import { FiBell, FiSearch, FiSettings } from 'react-icons/fi';
import { FaShieldAlt } from 'react-icons/fa';

export default function Header() {
  return (
    <header className="app-header">
      <div className="header-left">
        <FaShieldAlt size={22} color="var(--primary)" />
        <span className="header-logo">LARP SOC</span>
        <span style={{ background: 'var(--primary-light)', color: 'var(--primary)', fontSize: '0.7rem', fontWeight: 700, padding: '2px 8px', borderRadius: 'var(--radius-full)', letterSpacing: '0.05em' }}>LIVE</span>
      </div>
      <div className="header-right">
        <button className="header-icon-btn" title="Search"><FiSearch size={16} /></button>
        <button className="header-icon-btn" title="Notifications" style={{ position: 'relative' }}>
          <FiBell size={16} />
          <span style={{ position: 'absolute', top: 6, right: 6, width: 7, height: 7, background: 'var(--error)', borderRadius: '50%', border: '1.5px solid #fff' }} />
        </button>
        <button className="header-icon-btn" title="Settings"><FiSettings size={16} /></button>
        <div className="header-avatar" title="Admin">AD</div>
      </div>
    </header>
  );
}