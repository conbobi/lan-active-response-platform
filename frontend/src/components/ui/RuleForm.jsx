import React, { useState, useEffect } from 'react';
import Modal from './Modal';
import Button from './Button';
import { useAgents } from '../../hooks/useAgents';
import { FiSave, FiAlertTriangle, FiCode, FiLayers } from 'react-icons/fi';

const TYPE_OPTIONS = [
  { value: 'dns', label: 'DNS Spoofing Detection' },
  { value: 'proxy', label: 'Proxy Detection' },
  { value: 'botnet', label: 'Botnet Detection (IRC)' },
  { value: 'rate_limit', label: 'Rate Limit' },
  { value: 'blacklist', label: 'Blacklist' },
  { value: 'firewall', label: 'Firewall Rule' },
  { value: 'edr', label: 'EDR Rule' },
  { value: 'signature', label: 'Signature-based Rule' },
];

const SEVERITY_OPTIONS = [
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
];

const ACTION_OPTIONS = [
  { value: 'block', label: 'Block' },
  { value: 'alert', label: 'Alert' },
  { value: 'isolate', label: 'Isolate Agent' },
  { value: 'quarantine', label: 'Quarantine File' },
  { value: 'log', label: 'Log Only' },
];

const SCOPE_OPTIONS = [
  { value: 'all_agents', label: 'All Agents' },
  { value: 'selected_agents', label: 'Selected Agents' },
];

export default function RuleForm({ isOpen, onClose, onSubmit, onCheckConflicts, rule = null }) {
  const { agents = [] } = useAgents();
  const isEdit = Boolean(rule);

  const [mode, setMode] = useState('form'); // 'form' | 'json'

  const [formData, setFormData] = useState({
    name: '',
    description: '',
    type: 'dns',
    severity: 'high',
    status: 'active',
    action: 'alert',
    scope: 'all_agents',
    agent_ids: [],
    created_by: 'admin',
    // Dynamic condition fields
    internal_dns_servers: '192.168.1.1, 10.0.0.2',
    proxy_server_ip: '10.0.0.254',
    max_connections: 5000,
    time_window: 1,
    blocked_ips: '198.51.100.45, 203.0.113.88',
    blocked_domains: 'malware-c2-domain.com',
    allowed_ports: '22, 445',
    protocols: 'TCP',
    direction: 'inbound',
    signature_hash: '',
    pattern: '',
    // Raw json fallback
    raw_conditions: '{}',
  });

  const [conflicts, setConflicts] = useState([]);
  const [jsonError, setJsonError] = useState('');

  useEffect(() => {
    if (rule) {
      const cond = rule.conditions || {};
      setFormData({
        name: rule.name || '',
        description: rule.description || '',
        type: rule.type || 'dns',
        severity: rule.severity || 'high',
        status: rule.status || 'active',
        action: rule.action || 'alert',
        scope: rule.scope || 'all_agents',
        agent_ids: rule.agent_ids || (rule.selected_agents ? rule.selected_agents : []),
        created_by: rule.created_by || 'admin',

        internal_dns_servers: Array.isArray(cond.internal_dns_servers) ? cond.internal_dns_servers.join(', ') : '',
        proxy_server_ip: Array.isArray(cond.proxy_server_ip) ? cond.proxy_server_ip.join(', ') : '',
        max_connections: cond.max_connections || 5000,
        time_window: cond.time_window || 1,
        blocked_ips: Array.isArray(cond.blocked_ips) ? cond.blocked_ips.join(', ') : '',
        blocked_domains: Array.isArray(cond.blocked_domains) ? cond.blocked_domains.join(', ') : '',
        allowed_ports: Array.isArray(cond.allowed_ports) ? cond.allowed_ports.join(', ') : '',
        protocols: Array.isArray(cond.protocols) ? cond.protocols.join(', ') : cond.protocols || 'TCP',
        direction: cond.direction || 'inbound',
        signature_hash: cond.signature_hash || '',
        pattern: cond.pattern || '',
        raw_conditions: JSON.stringify(cond, null, 2),
      });
      setJsonError('');
    } else {
      setFormData({
        name: '',
        description: '',
        type: 'dns',
        severity: 'high',
        status: 'active',
        action: 'alert',
        scope: 'all_agents',
        agent_ids: [],
        created_by: 'admin',
        internal_dns_servers: '192.168.1.1, 10.0.0.2',
        proxy_server_ip: '10.0.0.254',
        max_connections: 5000,
        time_window: 1,
        blocked_ips: '198.51.100.45, 203.0.113.88',
        blocked_domains: 'malware-c2-domain.com',
        allowed_ports: '22',
        protocols: 'TCP',
        direction: 'inbound',
        signature_hash: '',
        pattern: '',
        raw_conditions: '{\n  "protocol": "DNS",\n  "dest_port": 53\n}',
      });
      setJsonError('');
    }
  }, [rule, isOpen]);

  // Real-time conflict check trigger
  useEffect(() => {
    if (onCheckConflicts && formData.name) {
      const candidate = buildPayload();
      if (rule && rule.id) candidate.id = rule.id;
      const found = onCheckConflicts(candidate);
      setConflicts(found);
    } else {
      setConflicts([]);
    }
  }, [formData.name, formData.type, formData.action, formData.allowed_ports, formData.blocked_ips]);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
  };

  const handleAgentToggle = (agentId) => {
    setFormData((prev) => {
      const exists = prev.agent_ids.includes(agentId);
      const updated = exists ? prev.agent_ids.filter((id) => id !== agentId) : [...prev.agent_ids, agentId];
      return { ...prev, agent_ids: updated };
    });
  };

  const buildPayload = () => {
    let conditionsObj = {};

    if (mode === 'json') {
      try {
        conditionsObj = JSON.parse(formData.raw_conditions);
      } catch (err) {
        throw new Error('Invalid JSON format in Conditions.');
      }
    } else {
      // Build conditions dynamically per type
      switch (formData.type) {
        case 'dns':
          conditionsObj = {
            protocol: 'DNS',
            dest_port: 53,
            internal_dns_servers: formData.internal_dns_servers.split(',').map((s) => s.trim()).filter(Boolean),
          };
          break;
        case 'proxy':
          conditionsObj = {
            protocol: 'HTTP/S',
            proxy_server_ip: formData.proxy_server_ip.split(',').map((s) => s.trim()).filter(Boolean),
          };
          break;
        case 'rate_limit':
          conditionsObj = {
            max_connections: Number(formData.max_connections) || 1000,
            time_window: Number(formData.time_window) || 1,
          };
          break;
        case 'blacklist':
          conditionsObj = {
            blocked_ips: formData.blocked_ips.split(',').map((s) => s.trim()).filter(Boolean),
            blocked_domains: formData.blocked_domains.split(',').map((s) => s.trim()).filter(Boolean),
          };
          break;
        case 'firewall':
          conditionsObj = {
            allowed_ports: formData.allowed_ports.split(',').map((s) => Number(s.trim())).filter((n) => !isNaN(n)),
            protocols: formData.protocols.split(',').map((s) => s.trim()).filter(Boolean),
            direction: formData.direction,
          };
          break;
        case 'edr':
        case 'signature':
        case 'botnet':
          conditionsObj = {
            pattern: formData.pattern,
            signature_hash: formData.signature_hash,
          };
          break;
        default:
          conditionsObj = {};
      }
    }

    return {
      name: formData.name,
      description: formData.description,
      type: formData.type,
      severity: formData.severity,
      status: formData.status,
      action: formData.action,
      scope: formData.scope,
      agent_ids: formData.scope === 'selected_agents' ? formData.agent_ids : [],
      created_by: formData.created_by,
      conditions: conditionsObj,
    };
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    try {
      const payload = buildPayload();
      onSubmit(payload);
      onClose();
    } catch (err) {
      setJsonError(err.message);
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={isEdit ? 'Edit Security Rule' : 'Create Security Rule'} maxWidth={700}>
      <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        {/* Top Header Mode Toggle */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Rule Parameters & Scope Definition</span>
          <div style={{ display: 'flex', gap: '0.25rem', background: 'var(--bg)', padding: '2px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
            <button
              type="button"
              className={`btn ${mode === 'form' ? 'btn-primary' : 'btn-ghost'}`}
              style={{ fontSize: '0.72rem', padding: '0.2rem 0.6rem' }}
              onClick={() => setMode('form')}
            >
              <FiLayers size={11} style={{ marginRight: 4 }} /> Form View
            </button>
            <button
              type="button"
              className={`btn ${mode === 'json' ? 'btn-primary' : 'btn-ghost'}`}
              style={{ fontSize: '0.72rem', padding: '0.2rem 0.6rem' }}
              onClick={() => setMode('json')}
            >
              <FiCode size={11} style={{ marginRight: 4 }} /> Raw JSON
            </button>
          </div>
        </div>

        {/* Conflict Alert Banner */}
        {conflicts.length > 0 && (
          <div style={{ padding: '0.75rem', background: 'rgba(245,158,11,0.1)', border: '1px solid var(--warning)', borderRadius: 'var(--radius-sm)' }}>
            <div style={{ fontWeight: 700, fontSize: '0.85rem', color: 'var(--warning)', display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.25rem' }}>
              <FiAlertTriangle size={15} /> Conflict Warning Detected
            </div>
            <ul style={{ margin: 0, paddingLeft: '1.2rem', fontSize: '0.78rem', color: 'var(--text-primary)' }}>
              {conflicts.map((c, i) => (
                <li key={i}>{c}</li>
              ))}
            </ul>
          </div>
        )}

        {/* Basic Fields */}
        <div>
          <label style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.3rem' }}>
            Rule Name <span style={{ color: 'var(--error)' }}>*</span>
          </label>
          <input
            type="text"
            name="name"
            required
            value={formData.name}
            onChange={handleChange}
            placeholder="e.g. DNS Spoofing Detection"
            style={{
              width: '100%',
              padding: '0.55rem 0.75rem',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius-sm)',
              fontSize: '0.875rem',
              background: 'var(--bg)',
              color: 'var(--text-primary)',
              outline: 'none',
            }}
          />
        </div>

        <div>
          <label style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.3rem' }}>
            Description
          </label>
          <textarea
            name="description"
            rows={2}
            value={formData.description}
            onChange={handleChange}
            placeholder="Brief explanation of policy target"
            style={{
              width: '100%',
              padding: '0.55rem 0.75rem',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius-sm)',
              fontSize: '0.875rem',
              background: 'var(--bg)',
              color: 'var(--text-primary)',
              outline: 'none',
              resize: 'vertical',
            }}
          />
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.75rem' }}>
          <div>
            <label style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.3rem' }}>
              Rule Type
            </label>
            <select
              name="type"
              value={formData.type}
              onChange={handleChange}
              style={{
                width: '100%',
                padding: '0.55rem 0.75rem',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.85rem',
                background: 'var(--bg)',
                color: 'var(--text-primary)',
                outline: 'none',
              }}
            >
              {TYPE_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.3rem' }}>
              Severity
            </label>
            <select
              name="severity"
              value={formData.severity}
              onChange={handleChange}
              style={{
                width: '100%',
                padding: '0.55rem 0.75rem',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.85rem',
                background: 'var(--bg)',
                color: 'var(--text-primary)',
                outline: 'none',
              }}
            >
              {SEVERITY_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.3rem' }}>
              Action
            </label>
            <select
              name="action"
              value={formData.action}
              onChange={handleChange}
              style={{
                width: '100%',
                padding: '0.55rem 0.75rem',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.85rem',
                background: 'var(--bg)',
                color: 'var(--text-primary)',
                outline: 'none',
              }}
            >
              {ACTION_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Dynamic Parameters per Rule Type */}
        {mode === 'form' ? (
          <div style={{ padding: '0.85rem', background: 'rgba(97,0,255,0.03)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)' }}>
            <div style={{ fontWeight: 700, fontSize: '0.82rem', color: 'var(--primary)', marginBottom: '0.5rem' }}>
              Specific Parameters ({formData.type.toUpperCase()})
            </div>

            {formData.type === 'dns' && (
              <div>
                <label style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.2rem' }}>
                  Internal DNS Servers (comma separated)
                </label>
                <input
                  type="text"
                  name="internal_dns_servers"
                  value={formData.internal_dns_servers}
                  onChange={handleChange}
                  placeholder="192.168.1.1, 10.0.0.2"
                  style={{ width: '100%', padding: '0.45rem 0.65rem', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', fontSize: '0.85rem', background: 'var(--bg)', color: 'var(--text-primary)', outline: 'none' }}
                />
              </div>
            )}

            {formData.type === 'proxy' && (
              <div>
                <label style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.2rem' }}>
                  Authorized Proxy Server IPs
                </label>
                <input
                  type="text"
                  name="proxy_server_ip"
                  value={formData.proxy_server_ip}
                  onChange={handleChange}
                  placeholder="10.0.0.254, 192.168.1.254"
                  style={{ width: '100%', padding: '0.45rem 0.65rem', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', fontSize: '0.85rem', background: 'var(--bg)', color: 'var(--text-primary)', outline: 'none' }}
                />
              </div>
            )}

            {formData.type === 'rate_limit' && (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                <div>
                  <label style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.2rem' }}>
                    Max Connections / Threshold
                  </label>
                  <input
                    type="number"
                    name="max_connections"
                    value={formData.max_connections}
                    onChange={handleChange}
                    style={{ width: '100%', padding: '0.45rem 0.65rem', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', fontSize: '0.85rem', background: 'var(--bg)', color: 'var(--text-primary)', outline: 'none' }}
                  />
                </div>
                <div>
                  <label style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.2rem' }}>
                    Time Window (seconds)
                  </label>
                  <input
                    type="number"
                    name="time_window"
                    value={formData.time_window}
                    onChange={handleChange}
                    style={{ width: '100%', padding: '0.45rem 0.65rem', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', fontSize: '0.85rem', background: 'var(--bg)', color: 'var(--text-primary)', outline: 'none' }}
                  />
                </div>
              </div>
            )}

            {formData.type === 'blacklist' && (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                <div>
                  <label style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.2rem' }}>
                    Blocked IPs (comma separated)
                  </label>
                  <input
                    type="text"
                    name="blocked_ips"
                    value={formData.blocked_ips}
                    onChange={handleChange}
                    placeholder="198.51.100.45, 203.0.113.88"
                    style={{ width: '100%', padding: '0.45rem 0.65rem', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', fontSize: '0.85rem', background: 'var(--bg)', color: 'var(--text-primary)', outline: 'none' }}
                  />
                </div>
                <div>
                  <label style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.2rem' }}>
                    Blocked Domains
                  </label>
                  <input
                    type="text"
                    name="blocked_domains"
                    value={formData.blocked_domains}
                    onChange={handleChange}
                    placeholder="malware-c2-domain.com"
                    style={{ width: '100%', padding: '0.45rem 0.65rem', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', fontSize: '0.85rem', background: 'var(--bg)', color: 'var(--text-primary)', outline: 'none' }}
                  />
                </div>
              </div>
            )}

            {formData.type === 'firewall' && (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.75rem' }}>
                <div>
                  <label style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.2rem' }}>
                    Ports (e.g. 22, 80, 443)
                  </label>
                  <input
                    type="text"
                    name="allowed_ports"
                    value={formData.allowed_ports}
                    onChange={handleChange}
                    style={{ width: '100%', padding: '0.45rem 0.65rem', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', fontSize: '0.85rem', background: 'var(--bg)', color: 'var(--text-primary)', outline: 'none' }}
                  />
                </div>
                <div>
                  <label style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.2rem' }}>
                    Protocols
                  </label>
                  <input
                    type="text"
                    name="protocols"
                    value={formData.protocols}
                    onChange={handleChange}
                    placeholder="TCP, UDP"
                    style={{ width: '100%', padding: '0.45rem 0.65rem', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', fontSize: '0.85rem', background: 'var(--bg)', color: 'var(--text-primary)', outline: 'none' }}
                  />
                </div>
                <div>
                  <label style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.2rem' }}>
                    Direction
                  </label>
                  <select
                    name="direction"
                    value={formData.direction}
                    onChange={handleChange}
                    style={{ width: '100%', padding: '0.45rem 0.65rem', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', fontSize: '0.85rem', background: 'var(--bg)', color: 'var(--text-primary)', outline: 'none' }}
                  >
                    <option value="inbound">Inbound</option>
                    <option value="outbound">Outbound</option>
                    <option value="both">Both</option>
                  </select>
                </div>
              </div>
            )}

            {(formData.type === 'edr' || formData.type === 'signature' || formData.type === 'botnet') && (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                <div>
                  <label style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.2rem' }}>
                    Pattern / Process String
                  </label>
                  <input
                    type="text"
                    name="pattern"
                    value={formData.pattern}
                    onChange={handleChange}
                    placeholder="e.g. lsass_access_dump"
                    style={{ width: '100%', padding: '0.45rem 0.65rem', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', fontSize: '0.85rem', background: 'var(--bg)', color: 'var(--text-primary)', outline: 'none' }}
                  />
                </div>
                <div>
                  <label style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.2rem' }}>
                    Signature Hash / Rule Key
                  </label>
                  <input
                    type="text"
                    name="signature_hash"
                    value={formData.signature_hash}
                    onChange={handleChange}
                    placeholder="e3b0c442..."
                    style={{ width: '100%', padding: '0.45rem 0.65rem', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', fontSize: '0.85rem', background: 'var(--bg)', color: 'var(--text-primary)', outline: 'none', fontFamily: 'monospace' }}
                  />
                </div>
              </div>
            )}
          </div>
        ) : (
          <div>
            <label style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.3rem' }}>
              Conditions Object (JSON)
            </label>
            <textarea
              name="raw_conditions"
              rows={5}
              value={formData.raw_conditions}
              onChange={handleChange}
              style={{
                width: '100%',
                padding: '0.55rem 0.75rem',
                border: jsonError ? '1px solid var(--error)' : '1px solid var(--border)',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.82rem',
                background: '#0d0e1a',
                color: '#68d391',
                outline: 'none',
                fontFamily: 'monospace',
              }}
            />
            {jsonError && <div style={{ color: 'var(--error)', fontSize: '0.78rem', marginTop: '0.25rem' }}>{jsonError}</div>}
          </div>
        )}

        {/* Scope and Agent Selector */}
        <div>
          <label style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.3rem' }}>
            Enforcement Scope
          </label>
          <select
            name="scope"
            value={formData.scope}
            onChange={handleChange}
            style={{
              width: '100%',
              padding: '0.55rem 0.75rem',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius-sm)',
              fontSize: '0.85rem',
              background: 'var(--bg)',
              color: 'var(--text-primary)',
              outline: 'none',
              marginBottom: '0.5rem',
            }}
          >
            {SCOPE_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>

          {formData.scope === 'selected_agents' && (
            <div style={{ border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: '0.75rem', background: 'var(--bg)' }}>
              <div style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>
                Select Target Agents ({formData.agent_ids.length} selected):
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.4rem', maxHeight: 130, overflowY: 'auto' }}>
                {agents.map((ag) => {
                  const isChecked = formData.agent_ids.includes(ag.id);
                  return (
                    <label key={ag.id} style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.78rem', cursor: 'pointer' }}>
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={() => handleAgentToggle(ag.id)}
                        style={{ accentColor: 'var(--primary)' }}
                      />
                      <span><strong>{ag.hostname}</strong> ({ag.ip})</span>
                    </label>
                  );
                })}
              </div>
            </div>
          )}
        </div>

        {/* Buttons */}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '0.5rem' }}>
          <Button variant="ghost" size="md" type="button" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" size="md" type="submit" iconLeft={<FiSave size={14} />}>
            {isEdit ? 'Update Rule' : 'Save Rule'}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
