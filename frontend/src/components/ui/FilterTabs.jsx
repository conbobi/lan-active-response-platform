import React from 'react';

export default function FilterTabs({ tabs, active, onChange }) {
  return (
    <div className="filter-tabs">
      {tabs.map((tab) => (
        <button
          key={tab.value}
          className={`filter-tab ${active === tab.value ? 'active' : ''}`}
          onClick={() => onChange(tab.value)}
        >
          {tab.label}
          {tab.count != null && (
            <span style={{ marginLeft: '0.4rem', opacity: 0.75 }}>({tab.count})</span>
          )}
        </button>
      ))}
    </div>
  );
}
