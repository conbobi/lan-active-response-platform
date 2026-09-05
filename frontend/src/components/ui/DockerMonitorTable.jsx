import React, { useState } from 'react';
import { FiLayers, FiRefreshCw, FiAlertTriangle, FiArrowDown, FiArrowUp } from 'react-icons/fi';

const formatBytes = (bytes) => {
  if (!bytes || bytes === 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
};

const getStatusBadge = (status) => {
  const s = (status || '').toLowerCase();
  let bg = 'rgba(100, 116, 139, 0.12)';
  let color = 'var(--text-secondary)';
  let dotColor = '#94a3b8';
  let label = status;

  if (s === 'running') {
    bg = 'rgba(0, 192, 123, 0.12)';
    color = 'var(--success)';
    dotColor = 'var(--success)';
    label = 'running';
  } else if (s === 'exited' || s === 'dead') {
    bg = 'rgba(239, 68, 68, 0.12)';
    color = 'var(--error)';
    dotColor = 'var(--error)';
    label = 'exited';
  } else if (s === 'restarting') {
    bg = 'rgba(245, 158, 11, 0.12)';
    color = 'var(--warning)';
    dotColor = 'var(--warning)';
    label = 'restarting';
  } else if (s === 'paused') {
    bg = 'rgba(59, 130, 246, 0.12)';
    color = 'var(--info)';
    dotColor = 'var(--info)';
    label = 'paused';
  }

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.35rem',
        padding: '0.2rem 0.6rem',
        borderRadius: '9999px',
        fontSize: '0.75rem',
        fontWeight: 600,
        textTransform: 'uppercase',
        letterSpacing: '0.5px',
        background: bg,
        color: color,
      }}
    >
      <span
        style={{
          width: 6,
          height: 6,
          borderRadius: '50%',
          background: dotColor,
        }}
      />
      {label}
    </span>
  );
};

export default function DockerMonitorTable({ containers = [], loading = false, error = null, onRefresh }) {
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');

  const filteredContainers = containers.filter((c) => {
    const matchName = (c.name || '').toLowerCase().includes(search.toLowerCase()) ||
                      (c.container_id || '').toLowerCase().includes(search.toLowerCase());
    const matchStatus = statusFilter === 'all' || (c.status || '').toLowerCase() === statusFilter;
    return matchName && matchStatus;
  });

  const runningCount = containers.filter((c) => (c.status || '').toLowerCase() === 'running').length;

  return (
    <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
      {/* Card Header */}
      <div
        className="table-header"
        style={{
          padding: '1rem 1.25rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: '0.75rem',
          borderBottom: '1px solid var(--border)',
          flexWrap: 'wrap',
          marginBottom: 0,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem' }}>
          <FiLayers size={18} color="var(--primary)" />
          <h3 style={{ fontWeight: 700, fontSize: '0.95rem', margin: 0 }}>Docker Containers Monitor</h3>
          <span className="badge badge-info" style={{ marginLeft: '0.25rem' }}>
            {runningCount}/{containers.length} Running
          </span>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <input
            placeholder="Search container..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{
              padding: '0.4rem 0.75rem',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius-full)',
              fontSize: '0.82rem',
              background: 'var(--bg)',
              color: 'var(--text-primary)',
              outline: 'none',
              width: 140,
            }}
          />

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            style={{
              padding: '0.4rem 0.6rem',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius-full)',
              fontSize: '0.82rem',
              background: 'var(--bg)',
              color: 'var(--text-primary)',
              outline: 'none',
            }}
          >
            <option value="all">All Status</option>
            <option value="running">Running</option>
            <option value="exited">Exited</option>
            <option value="restarting">Restarting</option>
          </select>

          {onRefresh && (
            <button
              onClick={onRefresh}
              className="action-btn"
              title="Refresh Docker Status"
              style={{
                width: 32,
                height: 32,
                borderRadius: '50%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                border: '1px solid var(--border)',
                background: 'var(--bg)',
                cursor: 'pointer',
              }}
            >
              <FiRefreshCw
                size={13}
                style={{
                  animation: loading ? 'spin 1s linear infinite' : 'none',
                  color: 'var(--text-secondary)',
                }}
              />
            </button>
          )}
        </div>
      </div>

      {/* Error Alert Banner */}
      {error && (
        <div
          style={{
            margin: '0.85rem 1.25rem',
            padding: '0.75rem 1rem',
            borderRadius: 'var(--radius-sm)',
            background: 'rgba(239, 68, 68, 0.08)',
            border: '1px solid rgba(239, 68, 68, 0.25)',
            display: 'flex',
            alignItems: 'center',
            gap: '0.6rem',
            color: 'var(--error)',
            fontSize: '0.82rem',
          }}
        >
          <FiAlertTriangle size={16} style={{ flexShrink: 0 }} />
          <div>
            <strong>Docker Connection Issue:</strong> {error}
            <span style={{ display: 'block', fontSize: '0.75rem', opacity: 0.85, marginTop: '0.15rem' }}>
              Ensure /var/run/docker.sock is mounted into the manager container.
            </span>
          </div>
        </div>
      )}

      {/* Containers Table */}
      <div style={{ overflowX: 'auto' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>Container Name</th>
              <th>Status</th>
              <th>CPU %</th>
              <th>RAM Usage</th>
              <th>Uptime</th>
              <th>Network (Rx / Tx)</th>
            </tr>
          </thead>
          <tbody>
            {filteredContainers.length === 0 ? (
              <tr>
                <td colSpan={6} style={{ textAlign: 'center', padding: '1.5rem', color: 'var(--text-tertiary)' }}>
                  {loading ? 'Fetching container metrics...' : error ? 'Docker daemon unavailable' : 'No containers found'}
                </td>
              </tr>
            ) : (
              filteredContainers.map((c) => {
                const memPercent = c.memory_limit > 0
                  ? Math.min(100, Math.round((c.memory_usage / c.memory_limit) * 100))
                  : 0;

                return (
                  <tr key={c.container_id}>
                    <td>
                      <div style={{ display: 'flex', flexDirection: 'column' }}>
                        <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{c.name}</span>
                        <span style={{ fontSize: '0.72rem', color: 'var(--text-tertiary)', fontFamily: 'monospace' }}>
                          {c.container_id}
                        </span>
                      </div>
                    </td>
                    <td>{getStatusBadge(c.status)}</td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', minWidth: 110 }}>
                        <div style={{ flex: 1, height: 5, background: 'var(--border)', borderRadius: 99, overflow: 'hidden' }}>
                          <div
                            style={{
                              height: '100%',
                              width: `${Math.min(100, c.cpu_percent)}%`,
                              background: c.cpu_percent > 80 ? 'var(--error)' : c.cpu_percent > 50 ? 'var(--warning)' : 'var(--success)',
                              borderRadius: 99,
                              transition: 'width 0.3s ease',
                            }}
                          />
                        </div>
                        <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', minWidth: 38, textAlign: 'right' }}>
                          {c.cpu_percent.toFixed(1)}%
                        </span>
                      </div>
                    </td>
                    <td>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem', minWidth: 120 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.78rem' }}>
                          <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>
                            {c.memory_usage} MB
                          </span>
                          {c.memory_limit > 0 && (
                            <span style={{ color: 'var(--text-tertiary)', fontSize: '0.72rem' }}>
                              / {c.memory_limit} MB
                            </span>
                          )}
                        </div>
                        {c.memory_limit > 0 && (
                          <div style={{ width: '100%', height: 4, background: 'var(--border)', borderRadius: 99, overflow: 'hidden' }}>
                            <div
                              style={{
                                height: '100%',
                                width: `${memPercent}%`,
                                background: memPercent > 85 ? 'var(--error)' : memPercent > 65 ? 'var(--warning)' : 'var(--primary)',
                                borderRadius: 99,
                                transition: 'width 0.3s ease',
                              }}
                            />
                          </div>
                        )}
                      </div>
                    </td>
                    <td>
                      <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                        {c.uptime || 'N/A'}
                      </span>
                    </td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                        <span style={{ display: 'flex', alignItems: 'center', gap: '0.15rem' }}>
                          <FiArrowDown size={11} color="var(--success)" />
                          {formatBytes(c.network_rx)}
                        </span>
                        <span style={{ display: 'flex', alignItems: 'center', gap: '0.15rem' }}>
                          <FiArrowUp size={11} color="var(--info)" />
                          {formatBytes(c.network_tx)}
                        </span>
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
