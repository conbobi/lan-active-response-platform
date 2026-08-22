// src/components/network/NetworkToolbar.jsx
import React from 'react';
import Button from '../ui/Button';
import Dropdown from '../ui/Dropdown';
import { FiZap, FiAlertTriangle, FiRefreshCw, FiCheckCircle, FiXCircle, FiNavigation, FiUnlock } from 'react-icons/fi';

export default function NetworkToolbar({
  agents = [],
  links = [],
  selectedFrom,
  setSelectedFrom,
  selectedTo,
  setSelectedTo,
  requiredBandwidth = 100,
  setRequiredBandwidth,
  onFindPath,
  onReleasePath,
  onSimulateFailure,
  onResetView,
  pathData,
}) {
  const agentOptions = agents.map((a) => ({
    value: a.id,
    label: `${a.name || a.hostname} (${a.ip || a.ip_address})`,
  }));

  const activeCount = links.filter((l) => l.isActive).length;
  const inactiveCount = links.filter((l) => !l.isActive).length;

  return (
    <div className="card" style={{ padding: '1rem 1.25rem', marginBottom: '1rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        {/* Controls Left */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', flexWrap: 'wrap' }}>
          <Dropdown
            label="Source Agent"
            options={agentOptions}
            value={selectedFrom}
            onChange={setSelectedFrom}
          />
          <Dropdown
            label="Target Agent"
            options={agentOptions}
            value={selectedTo}
            onChange={setSelectedTo}
          />

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
            <label style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', fontWeight: 500 }}>
              Bandwidth (Mbps)
            </label>
            <input
              type="number"
              min="1"
              max="10000"
              value={requiredBandwidth}
              onChange={(e) => setRequiredBandwidth && setRequiredBandwidth(Number(e.target.value))}
              style={{
                width: '120px',
                height: '36px',
                padding: '0 0.6rem',
                borderRadius: 'var(--radius-sm)',
                border: '1px solid var(--border)',
                background: 'var(--bg-secondary)',
                color: 'var(--text-primary)',
                fontSize: '0.85rem',
                outline: 'none',
              }}
            />
          </div>

          <Button variant="primary" size="md" iconLeft={<FiZap size={15} />} onClick={() => onFindPath && onFindPath()}>
            Find Path
          </Button>

          {pathData && pathData.found && (
            <Button variant="outline" size="md" iconLeft={<FiUnlock size={15} />} onClick={() => onReleasePath && onReleasePath()}>
              Release Path
            </Button>
          )}

          <Button variant="danger" size="md" iconLeft={<FiAlertTriangle size={15} />} onClick={() => onSimulateFailure && onSimulateFailure()}>
            Simulate Failure
          </Button>

          <Button variant="ghost" size="md" iconLeft={<FiRefreshCw size={15} />} onClick={() => onResetView && onResetView()}>
            Reset View
          </Button>
        </div>

        {/* Network Metrics Right */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
            <FiCheckCircle color="var(--success)" size={15} />
            <span>Active Links: <strong style={{ color: 'var(--text-primary)' }}>{activeCount}</strong></span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
            <FiXCircle color="var(--error)" size={15} />
            <span>Inactive: <strong style={{ color: 'var(--text-primary)' }}>{inactiveCount}</strong></span>
          </div>
        </div>
      </div>

      {/* Path Highlight Metrics Summary Banner */}
      {pathData && pathData.found && (
        <div
          style={{
            marginTop: '0.85rem',
            padding: '0.6rem 0.9rem',
            background: 'rgba(97,0,255,0.06)',
            border: '1px solid rgba(97,0,255,0.2)',
            borderRadius: 'var(--radius-sm)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '0.5rem',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.82rem', fontWeight: 600, color: 'var(--primary)' }}>
            <FiNavigation size={15} />
            <span>Optimal Route: {Array.isArray(pathData.path) ? pathData.path.join(' → ') : ''}</span>
          </div>

          <div style={{ display: 'flex', gap: '1.25rem', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
            <span>Session ID: <strong style={{ color: 'var(--text-primary)' }}>{pathData.session_id || 'N/A'}</strong></span>
            <span>Latency: <strong style={{ color: 'var(--text-primary)' }}>{pathData.totalLatency || pathData.total_latency || 0} ms</strong></span>
            <span>Allocated BW: <strong style={{ color: 'var(--text-primary)' }}>{pathData.allocatedBandwidth || pathData.avgBandwidth || pathData.allocated_bandwidth || 0} Mbps</strong></span>
            <span>Hops: <strong style={{ color: 'var(--text-primary)' }}>{(pathData.linkIds || pathData.link_ids || []).length}</strong></span>
          </div>
        </div>
      )}
    </div>
  );
}
