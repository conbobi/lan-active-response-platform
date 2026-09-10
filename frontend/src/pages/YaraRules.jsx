// src/pages/YaraRules.jsx
import React, { useState, useEffect } from 'react';
import axios from 'axios';
import Button from '../components/ui/Button';
import Badge from '../components/ui/Badge';
import {
  FiShield,
  FiPlus,
  FiPlay,
  FiTrash2,
  FiCode,
  FiCheckCircle,
  FiAlertTriangle,
  FiFolder
} from 'react-icons/fi';

const API_BASE = '/api/v1/yara';
const AGENTS_API = '/api/v1/agents';

const SAMPLE_RULE_TEMPLATE = `rule Custom_Malware_Pattern {
    meta:
        description = "Detects custom binary signature or script payload"
        author = "SOC Analyst"
    strings:
        $s1 = "malicious_string" nocase
        $s2 = { 4D 5A 90 00 } // MZ header
    condition:
        any of them
}`;

export default function YaraRules() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(false);
  const [agents, setAgents] = useState([]);
  const [selectedRule, setSelectedRule] = useState(null);

  // Modal states
  const [showAddModal, setShowAddModal] = useState(false);
  const [showScanModal, setShowScanModal] = useState(false);
  const [scanAgentId, setScanAgentId] = useState('');
  const [scanPath, setScanPath] = useState('/tmp');
  const [scanStatus, setScanStatus] = useState(null);

  const [newRule, setNewRule] = useState({
    name: '',
    category: 'malware',
    severity: 'critical',
    rule_content: SAMPLE_RULE_TEMPLATE,
  });

  const fetchRules = async () => {
    setLoading(true);
    try {
      const res = await axios.get(API_BASE);
      setRules(res.data);
      if (res.data.length > 0 && !selectedRule) {
        setSelectedRule(res.data[0]);
      }
    } catch (err) {
      console.error('Failed to load YARA rules:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchAgents = async () => {
    try {
      const res = await axios.get(AGENTS_API);
      setAgents(res.data || []);
      if (res.data.length > 0) {
        setScanAgentId(res.data[0].id);
      }
    } catch (err) {
      console.error('Failed to load agents:', err);
    }
  };

  useEffect(() => {
    fetchRules();
    fetchAgents();
  }, []);

  const handleCreateRule = async (e) => {
    e.preventDefault();
    try {
      await axios.post(API_BASE, newRule);
      setShowAddModal(false);
      setNewRule({
        name: '',
        category: 'malware',
        severity: 'critical',
        rule_content: SAMPLE_RULE_TEMPLATE,
      });
      await fetchRules();
    } catch (err) {
      alert('Error creating rule: ' + (err.response?.data?.error || err.message));
    }
  };

  const handleDeleteRule = async (ruleId) => {
    if (!window.confirm('Are you sure you want to delete this YARA rule?')) return;
    try {
      await axios.delete(`${API_BASE}/${ruleId}`);
      await fetchRules();
    } catch (err) {
      alert('Error deleting rule: ' + err.message);
    }
  };

  const handleToggleRule = async (rule) => {
    try {
      await axios.put(`${API_BASE}/${rule.id}`, { enabled: !rule.enabled });
      setRules(rules.map(r => r.id === rule.id ? { ...r, enabled: !r.enabled } : r));
    } catch (err) {
      alert('Failed to update rule: ' + err.message);
    }
  };

  const handleTriggerScan = async (e) => {
    e.preventDefault();
    setScanStatus('dispatching');
    try {
      const res = await axios.post(`${API_BASE}/scan`, {
        agent_id: scanAgentId,
        target_path: scanPath,
        recursive: true
      });
      setScanStatus('success');
      setTimeout(() => {
        setShowScanModal(false);
        setScanStatus(null);
      }, 1500);
    } catch (err) {
      alert('Scan trigger failed: ' + (err.response?.data?.detail || err.message));
      setScanStatus('error');
    }
  };

  return (
    <div>
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 className="page-title">YARA Malware Signatures</h1>
          <p className="page-subtitle">Pattern matching engine for binary payload identification, webshells, and ransomware</p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <Button
            variant="outline"
            size="sm"
            onClick={() => setShowScanModal(true)}
            iconLeft={<FiPlay size={14} />}
          >
            Dispatch Scan
          </Button>
          <Button
            variant="primary"
            size="sm"
            onClick={() => setShowAddModal(true)}
            iconLeft={<FiPlus size={14} />}
          >
            New Rule
          </Button>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '1.5rem' }}>
        {/* Rules Table */}
        <div className="card">
          <h3 style={{ fontSize: '1.05rem', fontWeight: 700, marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <FiShield color="var(--primary)" /> Signature Rules Library ({rules.length})
          </h3>

          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th>Rule Name</th>
                  <th>Category</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule) => (
                  <tr
                    key={rule.id}
                    style={{
                      cursor: 'pointer',
                      background: selectedRule?.id === rule.id ? 'rgba(59, 130, 246, 0.08)' : 'inherit'
                    }}
                    onClick={() => setSelectedRule(rule)}
                  >
                    <td>
                      <div style={{ fontWeight: 600 }}>{rule.name}</div>
                    </td>
                    <td>
                      <span className="badge badge-neutral" style={{ textTransform: 'capitalize' }}>{rule.category}</span>
                    </td>
                    <td>
                      <Badge
                        status={rule.severity === 'critical' ? 'critical' : 'warning'}
                        label={rule.severity.toUpperCase()}
                      />
                    </td>
                    <td>
                      <span
                        style={{
                          fontSize: '0.8rem',
                          fontWeight: 600,
                          color: rule.enabled ? 'var(--success)' : 'var(--text-tertiary)'
                        }}
                      >
                        {rule.enabled ? 'Active' : 'Disabled'}
                      </span>
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: '0.4rem' }} onClick={(e) => e.stopPropagation()}>
                        <Button
                          variant={rule.enabled ? 'warning' : 'outline'}
                          size="sm"
                          onClick={() => handleToggleRule(rule)}
                        >
                          {rule.enabled ? 'Disable' : 'Enable'}
                        </Button>
                        <Button
                          variant="danger"
                          size="sm"
                          onClick={() => handleDeleteRule(rule.id)}
                        >
                          <FiTrash2 size={12} />
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Selected Rule Code Viewer */}
        <div className="card">
          <h3 style={{ fontSize: '1.05rem', fontWeight: 700, marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <FiCode color="var(--primary)" /> Rule Definition
          </h3>

          {selectedRule ? (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.75rem', fontSize: '0.85rem' }}>
                <div><strong>Identifier:</strong> {selectedRule.name}</div>
                <div><strong>Category:</strong> {selectedRule.category}</div>
              </div>
              <pre
                style={{
                  background: '#0f172a',
                  color: '#38bdf8',
                  padding: '1rem',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: '0.82rem',
                  fontFamily: 'monospace',
                  overflowX: 'auto',
                  border: '1px solid #1e293b',
                  minHeight: '280px'
                }}
              >
                {selectedRule.rule_content}
              </pre>
            </div>
          ) : (
            <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-tertiary)' }}>
              Select a rule from the table to preview its syntax.
            </div>
          )}
        </div>
      </div>

      {/* Modal Add Rule */}
      {showAddModal && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
          <div className="card" style={{ width: '600px', maxWidth: '90%' }}>
            <h3 style={{ fontSize: '1.1rem', fontWeight: 700, marginBottom: '1rem' }}>Create New YARA Rule</h3>
            <form onSubmit={handleCreateRule} style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.75rem' }}>
                <div>
                  <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Rule Name</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g., Ransomware_Note"
                    value={newRule.name}
                    onChange={(e) => setNewRule({ ...newRule, name: e.target.value })}
                    style={{ width: '100%', padding: '0.5rem', background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '4px', color: 'inherit' }}
                  />
                </div>
                <div>
                  <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Category</label>
                  <select
                    value={newRule.category}
                    onChange={(e) => setNewRule({ ...newRule, category: e.target.value })}
                    style={{ width: '100%', padding: '0.5rem', background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '4px', color: 'inherit' }}
                  >
                    <option value="malware">Malware</option>
                    <option value="ransomware">Ransomware</option>
                    <option value="webshell">Webshell</option>
                    <option value="c2">C2 Tooling</option>
                  </select>
                </div>
                <div>
                  <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Severity</label>
                  <select
                    value={newRule.severity}
                    onChange={(e) => setNewRule({ ...newRule, severity: e.target.value })}
                    style={{ width: '100%', padding: '0.5rem', background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '4px', color: 'inherit' }}
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                  </select>
                </div>
              </div>

              <div>
                <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>YARA Rule Code</label>
                <textarea
                  rows={10}
                  required
                  value={newRule.rule_content}
                  onChange={(e) => setNewRule({ ...newRule, rule_content: e.target.value })}
                  style={{
                    width: '100%',
                    padding: '0.75rem',
                    fontFamily: 'monospace',
                    fontSize: '0.85rem',
                    background: '#0f172a',
                    color: '#38bdf8',
                    border: '1px solid var(--border)',
                    borderRadius: '4px'
                  }}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
                <Button variant="outline" size="sm" type="button" onClick={() => setShowAddModal(false)}>Cancel</Button>
                <Button variant="primary" size="sm" type="submit">Compile & Save</Button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal Dispatch Scan */}
      {showScanModal && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
          <div className="card" style={{ width: '450px', maxWidth: '90%' }}>
            <h3 style={{ fontSize: '1.1rem', fontWeight: 700, marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <FiPlay color="var(--primary)" /> Dispatch YARA Scan
            </h3>
            <form onSubmit={handleTriggerScan} style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              <div>
                <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Target Agent</label>
                <select
                  value={scanAgentId}
                  onChange={(e) => setScanAgentId(e.target.value)}
                  style={{ width: '100%', padding: '0.5rem', background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '4px', color: 'inherit' }}
                >
                  {agents.map(ag => (
                    <option key={ag.id} value={ag.id}>{ag.id} ({ag.ip_address})</option>
                  ))}
                </select>
              </div>
              <div>
                <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Target Scan Directory / Path</label>
                <input
                  type="text"
                  required
                  value={scanPath}
                  onChange={(e) => setScanPath(e.target.value)}
                  placeholder="/tmp or /app"
                  style={{ width: '100%', padding: '0.5rem', background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '4px', color: 'inherit' }}
                />
              </div>

              {scanStatus === 'success' && (
                <div style={{ color: 'var(--success)', fontSize: '0.85rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <FiCheckCircle /> Scan command dispatched successfully!
                </div>
              )}

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.5rem' }}>
                <Button variant="outline" size="sm" type="button" onClick={() => setShowScanModal(false)}>Cancel</Button>
                <Button variant="primary" size="sm" type="submit" disabled={scanStatus === 'dispatching'}>
                  {scanStatus === 'dispatching' ? 'Sending...' : 'Start Scan'}
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
