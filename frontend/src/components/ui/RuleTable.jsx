// src/components/ui/RuleTable.jsx
import React from 'react';
import Badge from './Badge';
import { FiEdit2, FiTrash2, FiShield, FiCpu, FiGlobe, FiAlertCircle, FiLock, FiSliders, FiList, FiTerminal } from 'react-icons/fi';

const typeBadgeMap = {
  dns: { label: 'DNS', icon: <FiGlobe size={12} />, color: 'rgba(59,130,246,0.1)', textColor: '#3b82f6' },
  proxy: { label: 'Proxy', icon: <FiGlobe size={12} />, color: 'rgba(168,85,247,0.1)', textColor: '#a855f7' },
  botnet: { label: 'Botnet', icon: <FiAlertCircle size={12} />, color: 'rgba(239,68,68,0.1)', textColor: '#ef4444' },
  rate_limit: { label: 'Rate Limit', icon: <FiSliders size={12} />, color: 'rgba(245,158,11,0.1)', textColor: '#f59e0b' },
  blacklist: { label: 'Blacklist', icon: <FiLock size={12} />, color: 'rgba(239,68,68,0.1)', textColor: '#ef4444' },
  firewall: { label: 'Firewall', icon: <FiShield size={12} />, color: 'rgba(0,192,123,0.1)', textColor: '#00c07b' },
  edr: { label: 'EDR', icon: <FiCpu size={12} />, color: 'rgba(97,0,255,0.1)', textColor: '#6100ff' },
  signature: { label: 'Signature', icon: <FiTerminal size={12} />, color: 'rgba(100,116,139,0.1)', textColor: '#64748b' },
};

const actionLabelMap = {
  block: { label: 'Block', color: 'var(--error)' },
  alert: { label: 'Alert', color: 'var(--warning)' },
  isolate: { label: 'Isolate', color: 'var(--primary)' },
  quarantine: { label: 'Quarantine', color: '#a855f7' },
  log: { label: 'Log', color: 'var(--info)' },
};

export default function RuleTable({ rules = [], onEdit, onDelete, onToggle }) {
  if (rules.length === 0) {
    return (
      <div style={{ padding: '3rem 1.5rem', textAlignment: 'center', textAlign: 'center', color: 'var(--text-secondary)' }}>
        <FiShield size={36} color="var(--text-tertiary)" style={{ marginBottom: '0.5rem' }} />
        <div style={{ fontWeight: 600, fontSize: '0.95rem', color: 'var(--text-primary)' }}>No security rules found</div>
        <div style={{ fontSize: '0.82rem', color: 'var(--text-tertiary)', marginTop: '0.2rem' }}>
          Try adjusting your search or filters to see more results.
        </div>
      </div>
    );
  }

  return (
    <div style={{ overflowX: 'auto' }}>
      <table className="data-table">
        <thead>
          <tr>
            <th>Status</th>
            <th>Rule Name</th>
            <th>Type</th>
            <th>Severity</th>
            <th>Action</th>
            <th>Scope</th>
            <th style={{ textAlign: 'right' }}>Actions</th>
          </tr>
        </thead>
        <tbody>
          {rules.map((rule) => {
            const typeInfo = typeBadgeMap[rule.type] || { label: rule.type, color: 'var(--primary-light)', textColor: 'var(--primary)' };
            const actionInfo = actionLabelMap[rule.action] || { label: rule.action, color: 'var(--text-secondary)' };
            const isActive = rule.status === 'active';

            return (
              <tr key={rule.id}>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <label className="switch">
                      <input
                        type="checkbox"
                        checked={isActive}
                        onChange={() => onToggle(rule.id)}
                      />
                      <span className="switch-slider" />
                    </label>
                    <Badge status={rule.status} showDot={false} />
                  </div>
                </td>
                <td style={{ maxWidth: 300 }}>
                  <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.875rem' }}>
                    {rule.name}
                  </div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', marginTop: 2 }}>
                    {rule.description}
                  </div>
                </td>
                <td>
                  <span
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '0.3rem',
                      padding: '0.25rem 0.6rem',
                      borderRadius: 'var(--radius-full)',
                      fontSize: '0.75rem',
                      fontWeight: 600,
                      background: typeInfo.color,
                      color: typeInfo.textColor,
                    }}
                  >
                    {typeInfo.icon}
                    {typeInfo.label}
                  </span>
                </td>
                <td>
                  <Badge status={rule.severity} label={rule.severity} showDot={false} />
                </td>
                <td>
                  <span style={{ fontWeight: 600, fontSize: '0.8rem', color: actionInfo.color }}>
                    {actionInfo.label}
                  </span>
                </td>
                <td>
                  <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                    {rule.scope === 'all_agents' ? (
                      'All Agents'
                    ) : (
                      <span title={rule.selected_agents?.join(', ')}>
                        {rule.selected_agents?.length || 0} Agents
                      </span>
                    )}
                  </span>
                </td>
                <td>
                  <div className="table-actions" style={{ justifyContent: 'flex-end' }}>
                    <button className="action-btn" title="Edit Rule" onClick={() => onEdit(rule)}>
                      <FiEdit2 size={13} />
                    </button>
                    <button className="action-btn danger" title="Delete Rule" onClick={() => onDelete(rule.id)}>
                      <FiTrash2 size={13} />
                    </button>
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
