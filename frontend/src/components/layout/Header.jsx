import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { FiBell, FiSearch, FiSettings, FiX, FiCpu, FiAlertOctagon, FiShield, FiArrowRight } from 'react-icons/fi';
import { FaShieldAlt } from 'react-icons/fa';
import { getAgents } from '../../api/agents';
import { getIncidents } from '../../api/incidents';

export default function Header() {
  const navigate = useNavigate();
  const [searchOpen, setSearchOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [agents, setAgents] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [unresolvedCount, setUnresolvedCount] = useState(0);

  useEffect(() => {
    getAgents().then(data => Array.isArray(data) && setAgents(data)).catch(() => []);
    getIncidents().then(data => {
      if (Array.isArray(data)) {
        setIncidents(data);
        const unresolved = data.filter(i => !['resolved', 'closed', 'false_positive'].includes(i.status?.toLowerCase()));
        setUnresolvedCount(unresolved.length);
      }
    }).catch(() => []);
  }, []);

  // Global Ctrl+K shortcut
  useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setSearchOpen(prev => !prev);
      } else if (e.key === 'Escape' && searchOpen) {
        setSearchOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [searchOpen]);

  const navItems = [
    { label: 'Security Dashboard', path: '/', category: 'Page' },
    { label: 'Security Incidents & Alerts', path: '/incidents', category: 'Page' },
    { label: 'Investigate (Process Tree & Network)', path: '/investigate', category: 'Page' },
    { label: 'Actions History & Rollback', path: '/actions', category: 'Page' },
    { label: 'Response Policies', path: '/policies', category: 'Page' },
    { label: 'Endpoints & Host Groups', path: '/agents', category: 'Page' },
    { label: 'Detection Studio (Rules & YARA)', path: '/detection', category: 'Page' },
    { label: 'SOC Settings & Thresholds', path: '/settings', category: 'Page' },
  ];

  const filteredNav = query.trim() ? navItems.filter(i => i.label.toLowerCase().includes(query.toLowerCase())) : [];
  const filteredAgents = query.trim() ? agents.filter(a =>
    (a.hostname && a.hostname.toLowerCase().includes(query.toLowerCase())) ||
    (a.id && a.id.toLowerCase().includes(query.toLowerCase())) ||
    (a.ip && a.ip.includes(query))
  ).slice(0, 4) : [];
  const filteredIncidents = query.trim() ? incidents.filter(i =>
    (i.agent_id && i.agent_id.toLowerCase().includes(query.toLowerCase())) ||
    (i.id && String(i.id).includes(query)) ||
    (i.title && i.title.toLowerCase().includes(query.toLowerCase())) ||
    (i.attack_type && i.attack_type.toLowerCase().includes(query.toLowerCase()))
  ).slice(0, 4) : [];

  const handleSelect = (path) => {
    navigate(path);
    setSearchOpen(false);
    setQuery('');
  };

  return (
    <>
      <header className="app-header">
        <div className="header-left" style={{ cursor: 'pointer' }} onClick={() => navigate('/')}>
          <FaShieldAlt size={22} color="var(--primary)" />
          <span className="header-logo">LARP SOC</span>
          <span style={{ background: 'var(--primary-light)', color: 'var(--primary)', fontSize: '0.7rem', fontWeight: 700, padding: '2px 8px', borderRadius: 'var(--radius-full)', letterSpacing: '0.05em' }}>LIVE</span>
        </div>
        <div className="header-right">
          <button
            className="header-icon-btn"
            title="Global Search (Ctrl+K)"
            onClick={() => setSearchOpen(true)}
            style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', padding: '0.35rem 0.6rem' }}
          >
            <FiSearch size={16} />
            <span style={{ fontSize: '0.7rem', opacity: 0.6, border: '1px solid var(--border-primary)', borderRadius: '4px', padding: '1px 5px' }}>Ctrl+K</span>
          </button>
          <button
            className="header-icon-btn"
            title={unresolvedCount > 0 ? `${unresolvedCount} Active Incidents` : 'Notifications'}
            style={{ position: 'relative' }}
            onClick={() => navigate('/incidents')}
          >
            <FiBell size={16} />
            {unresolvedCount > 0 && (
              <span
                style={{
                  position: 'absolute',
                  top: 2,
                  right: 2,
                  minWidth: 14,
                  height: 14,
                  fontSize: '0.62rem',
                  fontWeight: 800,
                  background: 'var(--error)',
                  color: '#ffffff',
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  border: '1.5px solid var(--bg-secondary)',
                }}
              >
                {unresolvedCount > 9 ? '9+' : unresolvedCount}
              </span>
            )}
          </button>
          <button
            className="header-icon-btn"
            title="SOC Settings"
            onClick={() => navigate('/settings')}
          >
            <FiSettings size={16} />
          </button>
          <div className="header-avatar" title="SOC Analyst Tier 1/2 · LARP Platform">SA</div>
        </div>
      </header>

      {/* Global Quick Search Modal (Ctrl+K) */}
      {searchOpen && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 9999,
            background: 'var(--bg-overlay)',
            backdropFilter: 'blur(4px)',
            display: 'flex',
            alignItems: 'flex-start',
            justifyContent: 'center',
            paddingTop: '10vh',
          }}
          onClick={() => setSearchOpen(false)}
        >
          <div
            style={{
              width: '100%',
              maxWidth: '560px',
              background: 'var(--bg-elevated)',
              border: '1px solid var(--border-strong)',
              borderRadius: 'var(--radius-lg)',
              boxShadow: 'var(--shadow-lg)',
              overflow: 'hidden',
            }}
            onClick={e => e.stopPropagation()}
          >
            <div style={{ display: 'flex', alignItems: 'center', padding: '0.85rem 1.25rem', borderBottom: '1px solid var(--border-primary)', gap: '0.75rem' }}>
              <FiSearch size={18} color="var(--primary)" />
              <input
                type="text"
                autoFocus
                placeholder="Search endpoints, incidents, PIDs, or navigation..."
                value={query}
                onChange={e => setQuery(e.target.value)}
                style={{
                  flex: 1,
                  background: 'transparent',
                  border: 'none',
                  outline: 'none',
                  color: 'var(--text-primary)',
                  fontSize: '0.95rem',
                  padding: 0,
                }}
              />
              <button
                onClick={() => setSearchOpen(false)}
                style={{ background: 'none', border: 'none', color: 'var(--text-tertiary)', cursor: 'pointer' }}
              >
                <FiX size={18} />
              </button>
            </div>

            <div style={{ maxHeight: '380px', overflowY: 'auto', padding: '0.5rem' }}>
              {!query.trim() && (
                <div style={{ padding: '0.75rem', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                  <div style={{ fontWeight: 600, color: 'var(--text-tertiary)', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Quick Navigation
                  </div>
                  {navItems.map(item => (
                    <div
                      key={item.path}
                      onClick={() => handleSelect(item.path)}
                      style={{
                        padding: '0.5rem 0.75rem',
                        borderRadius: 'var(--radius-sm)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        cursor: 'pointer',
                        color: 'var(--text-primary)',
                        fontSize: '0.85rem',
                      }}
                      onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-tertiary)'}
                      onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                    >
                      <span>{item.label}</span>
                      <FiArrowRight size={14} color="var(--text-tertiary)" />
                    </div>
                  ))}
                </div>
              )}

              {query.trim() && (
                <>
                  {filteredNav.length > 0 && (
                    <div style={{ marginBottom: '0.75rem' }}>
                      <div style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-tertiary)', padding: '0.35rem 0.75rem', textTransform: 'uppercase' }}>Pages</div>
                      {filteredNav.map(item => (
                        <div
                          key={item.path}
                          onClick={() => handleSelect(item.path)}
                          style={{
                            padding: '0.45rem 0.75rem',
                            borderRadius: 'var(--radius-sm)',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            cursor: 'pointer',
                            color: 'var(--text-primary)',
                            fontSize: '0.85rem',
                          }}
                          onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-tertiary)'}
                          onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                        >
                          <span>{item.label}</span>
                          <span style={{ fontSize: '0.75rem', color: 'var(--primary)' }}>{item.path}</span>
                        </div>
                      ))}
                    </div>
                  )}

                  {filteredAgents.length > 0 && (
                    <div style={{ marginBottom: '0.75rem' }}>
                      <div style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-tertiary)', padding: '0.35rem 0.75rem', textTransform: 'uppercase' }}>Endpoints</div>
                      {filteredAgents.map(a => (
                        <div
                          key={a.id}
                          onClick={() => handleSelect(`/investigate?agent=${encodeURIComponent(a.id)}`)}
                          style={{
                            padding: '0.45rem 0.75rem',
                            borderRadius: 'var(--radius-sm)',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            cursor: 'pointer',
                            color: 'var(--text-primary)',
                            fontSize: '0.85rem',
                          }}
                          onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-tertiary)'}
                          onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            <FiCpu size={14} color="var(--primary)" />
                            <span style={{ fontWeight: 600 }}>{a.hostname || a.id}</span>
                            <span style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)' }}>({a.ip || a.ip_address})</span>
                          </div>
                          <span style={{ fontSize: '0.72rem', color: 'var(--primary)' }}>Investigate →</span>
                        </div>
                      ))}
                    </div>
                  )}

                  {filteredIncidents.length > 0 && (
                    <div>
                      <div style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-tertiary)', padding: '0.35rem 0.75rem', textTransform: 'uppercase' }}>Incidents</div>
                      {filteredIncidents.map(inc => (
                        <div
                          key={inc.id}
                          onClick={() => handleSelect(`/incidents/${inc.id}`)}
                          style={{
                            padding: '0.45rem 0.75rem',
                            borderRadius: 'var(--radius-sm)',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            cursor: 'pointer',
                            color: 'var(--text-primary)',
                            fontSize: '0.85rem',
                          }}
                          onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-tertiary)'}
                          onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            <FiAlertOctagon size={14} color="var(--critical)" />
                            <span>{inc.title || inc.attack_type || `Incident #${inc.id}`}</span>
                            <span style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)' }}>on {inc.agent_id}</span>
                          </div>
                          <span style={{ fontSize: '0.72rem', color: 'var(--critical)' }}>Triage →</span>
                        </div>
                      ))}
                    </div>
                  )}

                  {filteredNav.length === 0 && filteredAgents.length === 0 && filteredIncidents.length === 0 && (
                    <div style={{ padding: '2rem 1rem', textAlign: 'center', color: 'var(--text-tertiary)', fontSize: '0.85rem' }}>
                      No matching pages, endpoints or incidents found for "{query}"
                    </div>
                  )}
                </>
              )}
            </div>

            <div style={{ padding: '0.5rem 1.25rem', background: 'var(--bg-secondary)', borderTop: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: 'var(--text-tertiary)' }}>
              <span>Press <kbd style={{ padding: '1px 4px', background: 'var(--bg-tertiary)', borderRadius: '3px' }}>Esc</kbd> to close</span>
              <span>Global SOC Navigator</span>
            </div>
          </div>
        </div>
      )}
    </>
  );
}