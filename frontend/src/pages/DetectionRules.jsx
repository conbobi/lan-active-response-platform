// src/pages/DetectionRules.jsx
import React, { useState, useMemo, useEffect } from 'react';
import useDetectionRules from '../hooks/useDetectionRules';
import Badge from '../components/ui/Badge';
import SearchBar from '../components/ui/SearchBar';
import Modal from '../components/ui/Modal';
import Button from '../components/ui/Button';
import {
  FiShield,
  FiPlus,
  FiTrash2,
  FiEdit2,
  FiRotateCw,
  FiFolder,
  FiEye,
  FiCheckCircle,
  FiAlertTriangle,
} from 'react-icons/fi';

const CATEGORIES = ['All', 'OS', 'Network', 'Process', 'Behavior'];

function WeightInput({ initialWeight, onSave }) {
  const [val, setVal] = useState(initialWeight);

  useEffect(() => {
    setVal(initialWeight);
  }, [initialWeight]);

  const handleBlur = () => {
    if (parseFloat(val) !== parseFloat(initialWeight)) {
      onSave(val);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter') {
      e.target.blur();
    }
  };

  return (
    <input
      type="number"
      step="0.1"
      min="0"
      max="1000"
      value={val}
      onChange={(e) => setVal(e.target.value)}
      onBlur={handleBlur}
      onKeyDown={handleKeyDown}
      title="Press Enter or click outside to save"
      style={{
        width: '70px',
        padding: '0.25rem 0.45rem',
        borderRadius: 'var(--radius-sm)',
        border: '1px solid var(--border)',
        background: 'var(--bg-secondary, #8e95d1ff)',
        color: 'var(--text-primary)',
        fontWeight: 600,
        fontSize: '0.85rem',
      }}
    />
  );
}

export default function DetectionRules() {
  const {
    rules,
    loading,
    error,
    refreshRules,
    handleToggleRule,
    handleUpdateWeight,
    handleUpdateBaseScore,
    handleUpdateRule,
    handleCreateRule,
    handleDeleteRule,
  } = useDetectionRules();

  const [search, setSearch] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('All');
  const [modalOpen, setModalOpen] = useState(false);
  const [detailModalOpen, setDetailModalOpen] = useState(false);
  const [viewingRule, setViewingRule] = useState(null);
  const [editRule, setEditRule] = useState(null);
  const [actionNotice, setActionNotice] = useState(null);

  // Form State
  const [ruleId, setRuleId] = useState('');
  const [ruleName, setRuleName] = useState('');
  const [ruleDesc, setRuleDesc] = useState('');
  const [ruleCategory, setRuleCategory] = useState('os');
  const [ruleWeight, setRuleWeight] = useState(1.0);
  const [ruleBaseScore, setRuleBaseScore] = useState(1.0);
  const [ruleEnabled, setRuleEnabled] = useState(true);
  const [ruleConfigJson, setRuleConfigJson] = useState('{}');
  const [formError, setFormError] = useState('');

  const showNotice = (msg, isError = false) => {
    setActionNotice({ msg, isError });
    setTimeout(() => setActionNotice(null), 4000);
  };

  const filteredRules = useMemo(() => {
    return rules.filter((r) => {
      const matchSearch =
        !search ||
        (r.rule_id && r.rule_id.toLowerCase().includes(search.toLowerCase())) ||
        (r.name && r.name.toLowerCase().includes(search.toLowerCase())) ||
        (r.description && r.description.toLowerCase().includes(search.toLowerCase()));

      const rCategory = (r.category || 'os').toLowerCase();
      const matchCategory =
        categoryFilter === 'All' || rCategory === categoryFilter.toLowerCase();

      return matchSearch && matchCategory;
    });
  }, [rules, search, categoryFilter]);

  // Group filtered rules by category
  const groupedRules = useMemo(() => {
    const groups = {};
    filteredRules.forEach((rule) => {
      const cat = (rule.category || 'os').toUpperCase();
      if (!groups[cat]) groups[cat] = [];
      groups[cat].push(rule);
    });
    return groups;
  }, [filteredRules]);

  const openCreateModal = () => {
    setEditRule(null);
    setRuleId(`custom_rule_${rules.length + 1}`);
    setRuleName('');
    setRuleDesc('');
    setRuleCategory('os');
    setRuleWeight(1.0);
    setRuleBaseScore(1.0);
    setRuleEnabled(true);
    setRuleConfigJson('{\n}');
    setFormError('');
    setModalOpen(true);
  };

  const openEditModal = (rule) => {
    setEditRule(rule);
    setRuleId(rule.rule_id);
    setRuleName(rule.name || '');
    setRuleDesc(rule.description || '');
    setRuleCategory(rule.category || 'os');
    setRuleWeight(rule.weight !== undefined ? rule.weight : 1.0);
    setRuleBaseScore(rule.base_score !== undefined ? rule.base_score : 1.0);
    setRuleEnabled(rule.enabled !== undefined ? rule.enabled : true);
    setRuleConfigJson(JSON.stringify(rule.config || {}, null, 2));
    setFormError('');
    setModalOpen(true);
  };

  const openDetailModal = (rule) => {
    setViewingRule(rule);
    setDetailModalOpen(true);
  };

  const handleToggle = async (rule_id) => {
    try {
      await handleToggleRule(rule_id);
      showNotice(`Updated rule status for ${rule_id}`);
    } catch (err) {
      showNotice(`Failed to toggle rule: ${err.message}`, true);
    }
  };

  const handleSaveWeight = async (rule_id, newWeight) => {
    try {
      await handleUpdateWeight(rule_id, newWeight);
      showNotice(`Updated risk weight for ${rule_id} to ${newWeight}`);
    } catch (err) {
      showNotice(`Failed to update weight: ${err.message}`, true);
    }
  };

  const handleSaveBaseScore = async (rule_id, newBaseScore) => {
    try {
      await handleUpdateBaseScore(rule_id, newBaseScore);
      showNotice(`Updated base score for ${rule_id} to ${newBaseScore}`);
    } catch (err) {
      showNotice(`Failed to update base score: ${err.message}`, true);
    }
  };

  const handleDelete = async (rule_id) => {
    if (window.confirm(`Are you sure you want to delete detection rule '${rule_id}'?`)) {
      try {
        await handleDeleteRule(rule_id);
        showNotice(`Deleted detection rule '${rule_id}'`);
      } catch (err) {
        showNotice(`Failed to delete rule: ${err.message}`, true);
      }
    }
  };

  const handleFormSubmit = async (e) => {
    e.preventDefault();
    setFormError('');
    let parsedConfig = {};
    try {
      parsedConfig = ruleConfigJson ? JSON.parse(ruleConfigJson) : {};
    } catch (err) {
      setFormError('Invalid JSON in Rule Configuration field');
      return;
    }

    const payload = {
      rule_id: ruleId,
      name: ruleName,
      description: ruleDesc,
      enabled: ruleEnabled,
      weight: parseFloat(ruleWeight) || 1.0,
      base_score: parseFloat(ruleBaseScore) || 1.0,
      category: ruleCategory,
      config: parsedConfig,
    };

    try {
      if (editRule) {
        await handleUpdateRule(ruleId, payload);
        showNotice(`Updated detection rule '${ruleId}'`);
      } else {
        await handleCreateRule(payload);
        showNotice(`Created new detection rule '${ruleId}'`);
      }
      setModalOpen(false);
    } catch (err) {
      setFormError(err.message || 'Failed to save rule');
    }
  };

  const getCategoryBadge = (cat) => {
    const c = (cat || 'os').toLowerCase();
    if (c === 'network') return <Badge status="info" label="NETWORK" showDot={false} />;
    if (c === 'process') return <Badge status="warning" label="PROCESS" showDot={false} />;
    if (c === 'behavior') return <Badge status="critical" label="BEHAVIOR" showDot={false} />;
    return <Badge status="online" label="OS" showDot={false} />;
  };

  if (loading) {
    return (
      <div>
        <div className="page-header">
          <h1 className="page-title">Detection Rules Engine</h1>
        </div>
        <div className="card skeleton" style={{ height: '400px' }} />
      </div>
    );
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Detection Rules Engine</h1>
          <p className="page-subtitle">Configure core threat detection risk rules, base scores, weight factors, categories, and parameters</p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <Button variant="outline" iconLeft={<FiRotateCw size={15} />} onClick={refreshRules}>
            Refresh
          </Button>
          <Button variant="primary" iconLeft={<FiPlus size={15} />} onClick={openCreateModal}>
            Add Detection Rule
          </Button>
        </div>
      </div>

      {actionNotice && (
        <div
          style={{
            marginBottom: '1rem',
            padding: '0.75rem 1rem',
            borderRadius: 'var(--radius-md)',
            background: actionNotice.isError ? 'rgba(239, 68, 68, 0.15)' : 'rgba(0, 192, 123, 0.15)',
            border: `1px solid ${actionNotice.isError ? 'var(--error)' : 'var(--success)'}`,
            color: actionNotice.isError ? 'var(--error)' : 'var(--success)',
            fontSize: '0.875rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
          }}
        >
          {actionNotice.isError ? <FiAlertTriangle size={16} /> : <FiCheckCircle size={16} />}
          {actionNotice.msg}
        </div>
      )}

      {error && (
        <div
          style={{
            marginBottom: '1rem',
            padding: '0.75rem 1rem',
            borderRadius: 'var(--radius-md)',
            background: 'rgba(239, 68, 68, 0.15)',
            border: '1px solid var(--error)',
            color: 'var(--error)',
            fontSize: '0.875rem',
          }}
        >
          Error loading rules: {error}
        </div>
      )}

      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div
          style={{
            padding: '1rem 1.25rem',
            borderBottom: '1px solid var(--border)',
            display: 'flex',
            alignItems: 'center',
            justify: 'space-between',
            gap: '1rem',
            flexWrap: 'wrap',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <FiShield size={18} color="var(--primary)" />
            <span style={{ fontSize: '0.9rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
              Active Rules: <strong>{rules.filter((r) => r.enabled).length} / {rules.length}</strong>
            </span>
          </div>

          <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap' }}>
            <div
              style={{
                display: 'flex',
                gap: '0.25rem',
                background: 'var(--bg-secondary, #16182a)',
                padding: '0.25rem',
                borderRadius: 'var(--radius-full)',
                border: '1px solid var(--border)',
              }}
            >
              {CATEGORIES.map((cat) => (
                <button
                  key={cat}
                  onClick={() => setCategoryFilter(cat)}
                  style={{
                    padding: '0.3rem 0.75rem',
                    borderRadius: 'var(--radius-full)',
                    border: 'none',
                    background: categoryFilter === cat ? 'var(--primary)' : 'transparent',
                    color: categoryFilter === cat ? '#ffffff' : 'var(--text-secondary)',
                    fontSize: '0.75rem',
                    fontWeight: 600,
                    cursor: 'pointer',
                    transition: 'all 0.2s ease',
                  }}
                >
                  {cat}
                </button>
              ))}
            </div>
            <SearchBar value={search} onChange={setSearch} placeholder="Search detection rules…" style={{ width: 230 }} />
          </div>
        </div>

        <div style={{ overflowX: 'auto' }}>
          {Object.keys(groupedRules).length === 0 ? (
            <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-tertiary)' }}>
              No rules found matching criteria
            </div>
          ) : (
            Object.entries(groupedRules).map(([catName, catRules]) => (
              <div key={catName}>
                <div
                  style={{
                    background: 'rgba(97, 0, 255, 0.05)',
                    padding: '0.65rem 1.25rem',
                    borderBottom: '1px solid var(--border)',
                    fontWeight: 700,
                    fontSize: '0.8rem',
                    color: 'var(--primary)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.4rem',
                    letterSpacing: '0.05em',
                  }}
                >
                  <FiFolder size={14} /> CATEGORY: {catName} ({catRules.length})
                </div>
                <table className="data-table" style={{ width: '100%' }}>
                  <thead>
                    <tr>
                      <th style={{ width: '15%' }}>Rule ID</th>
                      <th style={{ width: '10%' }}>Category</th>
                      <th style={{ width: '37%' }}>Rule Name & Description</th>
                      <th style={{ width: '12%' }}>Base Score</th>
                      <th style={{ width: '12%' }}>Risk Weight</th>
                      <th style={{ width: '6%' }}>Status</th>
                      <th style={{ width: '8%', textAlign: 'right' }}>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {catRules.map((rule) => (
                      <tr key={rule.rule_id || rule.id}>
                        <td style={{ fontWeight: 700, color: 'var(--primary)', fontFamily: 'monospace' }}>
                          {rule.rule_id}
                        </td>
                        <td>{getCategoryBadge(rule.category)}</td>
                        <td>
                          <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{rule.name}</div>
                          <div style={{ fontSize: '0.78rem', color: 'var(--text-tertiary)', marginTop: '0.2rem' }}>
                            {rule.description}
                          </div>
                        </td>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                            <WeightInput
                              initialWeight={rule.base_score !== undefined ? rule.base_score : 1.0}
                              onSave={(newScore) => handleSaveBaseScore(rule.rule_id, newScore)}
                            />
                            <span style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)' }}>score</span>
                          </div>
                        </td>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                            <WeightInput
                              initialWeight={rule.weight !== undefined ? rule.weight : 1.0}
                              onSave={(newW) => handleSaveWeight(rule.rule_id, newW)}
                            />
                            <span style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)' }}>mult</span>
                          </div>
                        </td>
                        <td>
                          <label className="switch">
                            <input
                              type="checkbox"
                              checked={!!rule.enabled}
                              onChange={() => handleToggle(rule.rule_id)}
                            />
                            <span className="switch-slider" />
                          </label>
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <div style={{ display: 'flex', gap: '0.3rem', justifyContent: 'flex-end' }}>
                            <button
                              className="action-btn"
                              title="View Rule Details"
                              onClick={() => openDetailModal(rule)}
                            >
                              <FiEye size={14} />
                            </button>
                            <button
                              className="action-btn"
                              title="Edit Rule"
                              onClick={() => openEditModal(rule)}
                            >
                              <FiEdit2 size={14} />
                            </button>
                            <button
                              className="action-btn danger"
                              title="Delete Rule"
                              onClick={() => handleDelete(rule.rule_id)}
                            >
                              <FiTrash2 size={14} />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Modal Form (Create / Edit) */}
      <Modal isOpen={modalOpen} onClose={() => setModalOpen(false)} title={editRule ? `Edit Rule (${editRule.rule_id})` : 'Create Detection Rule'}>
        {formError && (
          <div style={{ marginBottom: '1rem', padding: '0.5rem 0.75rem', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid var(--error)', borderRadius: 'var(--radius-sm)', color: 'var(--error)', fontSize: '0.82rem' }}>
            {formError}
          </div>
        )}

        <form onSubmit={handleFormSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div>
            <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.25rem' }}>Rule ID</label>
            <input
              type="text"
              value={ruleId}
              onChange={(e) => setRuleId(e.target.value)}
              disabled={!!editRule}
              placeholder="e.g. lateral_movement"
              style={{ width: '100%', padding: '0.5rem 0.75rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)', background: 'var(--bg-secondary, #FDFFF5)', color: 'var(--text-primary)', fontFamily: 'monospace' }}
              required
            />
          </div>

          <div>
            <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.25rem' }}>Rule Name</label>
            <input
              type="text"
              value={ruleName}
              onChange={(e) => setRuleName(e.target.value)}
              placeholder="e.g. Lateral Movement Detection"
              style={{ width: '100%', padding: '0.5rem 0.75rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)', background: 'var(--bg-secondary, #FDFFF5)', color: 'var(--text-primary)' }}
              required
            />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1rem' }}>
            <div>
              <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.25rem' }}>Category</label>
              <select
                value={ruleCategory}
                onChange={(e) => setRuleCategory(e.target.value)}
                style={{ width: '100%', padding: '0.5rem 0.75rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)', background: 'var(--bg-secondary, #FDFFF5)', color: 'var(--text-primary)' }}
              >
                <option value="os">OS</option>
                <option value="network">Network</option>
                <option value="process">Process</option>
                <option value="behavior">Behavior</option>
              </select>
            </div>

            <div>
              <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.25rem' }}>Base Score</label>
              <input
                type="number"
                step="0.1"
                min="0.1"
                max="1000"
                value={ruleBaseScore}
                onChange={(e) => setRuleBaseScore(e.target.value)}
                style={{ width: '100%', padding: '0.5rem 0.75rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)', background: 'var(--bg-secondary, #FDFFF5)', color: 'var(--text-primary)' }}
                required
              />
            </div>

            <div>
              <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.25rem' }}>Risk Weight</label>
              <input
                type="number"
                step="0.1"
                min="0.1"
                max="100"
                value={ruleWeight}
                onChange={(e) => setRuleWeight(e.target.value)}
                style={{ width: '100%', padding: '0.5rem 0.75rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)', background: 'var(--bg-secondary, #FDFFF5)', color: 'var(--text-primary)' }}
                required
              />
            </div>
          </div>

          <div>
            <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.25rem' }}>Description</label>
            <textarea
              rows={2}
              value={ruleDesc}
              onChange={(e) => setRuleDesc(e.target.value)}
              placeholder="Describe what threat behavior this rule detects..."
              style={{ width: '100%', padding: '0.5rem 0.75rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)', background: 'var(--bg-secondary, #FDFFF5)', color: 'var(--text-primary)' }}
            />
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <label className="switch">
              <input
                type="checkbox"
                checked={ruleEnabled}
                onChange={(e) => setRuleEnabled(e.target.checked)}
              />
              <span className="switch-slider" />
            </label>
            <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)' }}>Rule Enabled</span>
          </div>

          <div>
            <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.25rem' }}>Rule Parameters Config (JSON)</label>
            <textarea
              rows={4}
              value={ruleConfigJson}
              onChange={(e) => setRuleConfigJson(e.target.value)}
              placeholder='{ "threshold": 80 }'
              style={{ width: '100%', padding: '0.5rem 0.75rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)', background: 'var(--bg-secondary, #FDFFF5)', color: 'var(--text-primary)', fontFamily: 'monospace', fontSize: '0.8rem' }}
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.5rem' }}>
            <Button variant="ghost" type="button" onClick={() => setModalOpen(false)}>
              Cancel
            </Button>
            <Button variant="primary" type="submit">
              Save Rule
            </Button>
          </div>
        </form>
      </Modal>

      {/* Modal View Details */}
      {viewingRule && (
        <Modal isOpen={detailModalOpen} onClose={() => setDetailModalOpen(false)} title={`Detection Rule Details: ${viewingRule.rule_id}`}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
              <div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', textTransform: 'uppercase' }}>Rule ID</span>
                <div style={{ fontWeight: 700, fontFamily: 'monospace', color: 'var(--primary)' }}>{viewingRule.rule_id}</div>
              </div>
              <div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', textTransform: 'uppercase' }}>Category</span>
                <div>{getCategoryBadge(viewingRule.category)}</div>
              </div>
            </div>

            <div>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', textTransform: 'uppercase' }}>Rule Name</span>
              <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{viewingRule.name}</div>
            </div>

            <div>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', textTransform: 'uppercase' }}>Description</span>
              <div style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>{viewingRule.description || 'No description provided'}</div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1rem' }}>
              <div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', textTransform: 'uppercase' }}>Base Score</span>
                <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{viewingRule.base_score ?? 1.0} base score</div>
              </div>
              <div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', textTransform: 'uppercase' }}>Risk Weight</span>
                <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{viewingRule.weight} multiplier</div>
              </div>
              <div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', textTransform: 'uppercase' }}>Enabled</span>
                <div style={{ fontWeight: 600, color: viewingRule.enabled ? 'var(--success)' : 'var(--error)' }}>
                  {viewingRule.enabled ? 'Active' : 'Disabled'}
                </div>
              </div>
            </div>

            <div>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', textTransform: 'uppercase' }}>Config JSON</span>
              <pre
                style={{
                  background: 'var(--bg-secondary, #16182a)',
                  padding: '0.75rem',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--border)',
                  color: 'var(--text-primary)',
                  fontSize: '0.8rem',
                  marginTop: '0.25rem',
                  overflowX: 'auto',
                }}
              >
                {JSON.stringify(viewingRule.config || {}, null, 2)}
              </pre>
            </div>

            {viewingRule.created_at && (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', fontSize: '0.75rem', color: 'var(--text-tertiary)' }}>
                <div>Created: {new Date(viewingRule.created_at).toLocaleString()}</div>
                <div>Updated: {new Date(viewingRule.updated_at || viewingRule.created_at).toLocaleString()}</div>
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '0.5rem' }}>
              <Button variant="outline" onClick={() => setDetailModalOpen(false)}>
                Close
              </Button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}

