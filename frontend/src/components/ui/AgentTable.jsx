import React, { useState } from 'react';
import { FiEye, FiSlash, FiLock, FiUnlock, FiServer } from 'react-icons/fi';
import Badge from './Badge';

export default function AgentTable({ agents, onViewAgent }) {
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState('all');
  const rows = agents
    .filter((a) => {
      const ms = a.hostname.toLowerCase().includes(search.toLowerCase());
      const mf = filter === 'all' || a.status === filter;
      return ms && mf;
    })
    .slice(0, 8);

  return (
    <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
      <div className="table-header" style={{ padding: '1rem 1.25rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.75rem', borderBottom: '1px solid var(--border)', flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <FiServer size={16} color="var(--primary)" />
          <h3 style={{ fontWeight: 700, fontSize: '0.95rem' }}>Agents Overview</h3>
          <span className="badge badge-info" style={{ marginLeft: '0.25rem' }}>{agents.length}</span>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <input
            placeholder="Search…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{ padding: '0.4rem 0.75rem', border: '1px solid var(--border)', borderRadius: 'var(--radius-full)', fontSize: '0.82rem', background: 'var(--bg)', color: 'var(--text-primary)', outline: 'none', width: 130 }}
          />
          <select
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            style={{ padding: '0.4rem 0.6rem', border: '1px solid var(--border)', borderRadius: 'var(--radius-full)', fontSize: '0.82rem', background: 'var(--bg)', color: 'var(--text-primary)', outline: 'none' }}
          >
            <option value="all">All</option>
            <option value="online">Online</option>
            <option value="offline">Offline</option>
          </select>
        </div>
      </div>
      <div style={{ overflowX: 'auto' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>Hostname</th><th>Status</th><th>CPU</th><th>RAM</th><th>Firewall</th><th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((a) => (
              <tr key={a.id}>
                <td style={{ fontWeight: 500 }}>{a.hostname}</td>
                <td><Badge status={a.status} /></td>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                    <div style={{ flex: 1, height: 4, background: 'var(--border)', borderRadius: 99, overflow: 'hidden' }}>
                      <div style={{ height: '100%', width: `${a.cpu}%`, background: a.cpu > 80 ? 'var(--error)' : a.cpu > 60 ? 'var(--warning)' : 'var(--success)', borderRadius: 99 }} />
                    </div>
                    <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', minWidth: 28 }}>{a.cpu}%</span>
                  </div>
                </td>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                    <div style={{ flex: 1, height: 4, background: 'var(--border)', borderRadius: 99, overflow: 'hidden' }}>
                      <div style={{ height: '100%', width: `${a.ram}%`, background: a.ram > 80 ? 'var(--error)' : a.ram > 60 ? 'var(--warning)' : 'var(--primary)', borderRadius: 99 }} />
                    </div>
                    <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', minWidth: 28 }}>{a.ram}%</span>
                  </div>
                </td>
                <td>
                  {a.firewall
                    ? <span style={{ color: 'var(--success)', fontSize: '0.8rem', fontWeight: 600 }}>Active</span>
                    : <span style={{ color: 'var(--error)', fontSize: '0.8rem' }}>Off</span>}
                </td>
                <td>
                  <div className="table-actions">
                    <button className="action-btn" title="View" onClick={() => onViewAgent && onViewAgent(a)}><FiEye size={13} /></button>
                    <button className="action-btn danger" title="Block"><FiSlash size={13} /></button>
                    <button className="action-btn" title="Isolate"><FiLock size={13} /></button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}