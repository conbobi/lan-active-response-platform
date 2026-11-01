// src/pages/Investigate.jsx
import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import ProcessTree from './ProcessTree';
import NetworkOverview from './NetworkOverview';
import ThreatIntel from './ThreatIntel';
import { FiCpu, FiGlobe, FiSearch } from 'react-icons/fi';

const TABS = [
  { id: 'process', label: 'Process Root Cause', icon: <FiCpu size={16} /> },
  { id: 'network', label: 'Network Flows', icon: <FiGlobe size={16} /> },
  { id: 'threat-intel', label: 'IoC Threat Lookup', icon: <FiSearch size={16} /> },
];

export default function Investigate({ initialTab }) {
  const [searchParams, setSearchParams] = useSearchParams();
  const urlTab = searchParams.get('tab') || initialTab || 'process';
  const [activeTab, setActiveTab] = useState(urlTab);

  useEffect(() => {
    const qTab = searchParams.get('tab');
    if (qTab && qTab !== activeTab) {
      setActiveTab(qTab);
    }
  }, [searchParams]);

  const handleTabChange = (tabId) => {
    setActiveTab(tabId);
    searchParams.set('tab', tabId);
    setSearchParams(searchParams);
  };

  return (
    <div>
      {/* Investigation Hub Header Navigation */}
      <div
        style={{
          display: 'flex',
          borderBottom: '1px solid var(--border-primary)',
          marginBottom: '1.25rem',
          gap: '0.5rem',
          background: 'var(--bg-secondary)',
          padding: '0.25rem 0.75rem 0 0.75rem',
          borderRadius: 'var(--radius-md) var(--radius-md) 0 0',
        }}
      >
        {TABS.map((tab) => {
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => handleTabChange(tab.id)}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.5rem',
                padding: '0.75rem 1.25rem',
                background: isActive ? 'var(--bg-elevated)' : 'transparent',
                color: isActive ? 'var(--primary)' : 'var(--text-secondary)',
                border: 'none',
                borderBottom: `2px solid ${isActive ? 'var(--primary)' : 'transparent'}`,
                cursor: 'pointer',
                fontWeight: isActive ? 700 : 500,
                fontSize: '0.9rem',
                transition: 'all 0.15s ease',
                borderRadius: 'var(--radius-sm) var(--radius-sm) 0 0',
              }}
            >
              {tab.icon}
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* Tab Panels */}
      <div>
        {activeTab === 'process' && <ProcessTree embedded={true} />}
        {activeTab === 'network' && <NetworkOverview />}
        {activeTab === 'threat-intel' && <ThreatIntel />}
      </div>
    </div>
  );
}
