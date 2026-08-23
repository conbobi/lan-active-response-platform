// src/pages/DetectionRules.jsx
import React, { useState, useMemo } from 'react';
import useDetectionRules from '../hooks/useDetectionRules';
import Badge from '../components/ui/Badge';
import SearchBar from '../components/ui/SearchBar';
import Modal from '../components/ui/Modal';
import Button from '../components/ui/Button';
import { FiShield, FiPlus, FiTrash2, FiEdit2, FiRotateCw } from 'react-icons/fi';

export default function DetectionRules() {
  const {
    rules,
    loading,
    refreshRules,
    handleToggleRule,
    handleUpdateWeight,
    handleCreateRule,
    handleDeleteRule,
  } = useDetectionRules();

  const [search, setSearch] = useState('');
  const [modalOpen, setModalOpen] = useState(false);
  const [editRule, setEditRule] = useState(null);

  // Form State
  const [ruleId, setRuleId] = useState('');
  const [ruleName, setRuleName] = useState('');
  const [ruleDesc, setRuleDesc] = useState('');
  const [ruleWeight, setRuleWeight] = useState(20);
  const [ruleConfigJson, setRuleConfigJson] = useState('{}');

  const filteredRules = useMemo(() => {
    return rules.filter(
      (r) =>
        !search ||
        r.rule_id.toLowerCase().includes(search.toLowerCase()) ||
        r.name.toLowerCase().includes(search.toLowerCase()) ||
        r.description.toLowerCase().includes(search.toLowerCase())
    );
  }, [rules, search]);

  const openCreateModal = () => {
    setEditRule(null);
    setRuleId(`R-${String(rules.length + 1).padStart(2, '0')}`);
    setRuleName('');
    setRuleDesc('');
    setRuleWeight(20);
    setRuleConfigJson('{}');
    setModalOpen(true);
  };

  const openEditModal = (rule) => {
    setEditRule(rule);
    setRuleId(rule.rule_id);
    setRuleName(rule.name);
    setRuleDesc(rule.description);
    setRuleWeight(rule.weight);
    setRuleConfigJson(JSON.stringify(rule.config || {}, null, 2));
    setModalOpen(true);
  };

  const handleFormSubmit = async (e) => {
    e.preventDefault();
    let parsedConfig = {};
    try {
      parsedConfig = JSON.parse(ruleConfigJson);
    } catch (err) {
      parsedConfig = {};
    }

    const payload = {
      rule_id: ruleId,
      name: ruleName,
      description: ruleDesc,
      enabled: editRule ? editRule.enabled : true,
      weight: Number(ruleWeight),
      config: parsedConfig,
    };

    if (editRule) {
      await handleUpdateWeight(ruleId, ruleWeight);
    } else {
      await handleCreateRule(payload);
    }

    setModalOpen(false);
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
          <p className="page-subtitle">Configure 13 core behavioral threat detection rules, risk weights, and telemetry thresholds</p>
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

      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ padding: '1rem 1.25rem', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
            Active Rules Count: <strong>{rules.filter((r) => r.enabled).length} / {rules.length}</strong>
          </span>
          <SearchBar value={search} onChange={setSearch} placeholder="Search 13 detection rules..." style={{ width: 280 }} />
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.875rem' }}>
            <thead>
              <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)', color: 'var(--text-secondary)' }}>
                <th style={{ padding: '0.85rem 1.25rem' }}>Rule ID</th>
                <th style={{ padding: '0.85rem 1.25rem' }}>Rule Name & Description</th>
                <th style={{ padding: '0.85rem 1.25rem' }}>Risk Weight</th>
                <th style={{ padding: '0.85rem 1.25rem' }}>Status</th>
                <th style={{ padding: '0.85rem 1.25rem', textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredRules.map((rule) => (
                <tr key={rule.rule_id} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '0.85rem 1.25rem', fontWeight: 700, color: 'var(--primary)' }}>
                    {rule.rule_id}
                  </td>
                  <td style={{ padding: '0.85rem 1.25rem' }}>
                    <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{rule.name}</div>
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-tertiary)', marginTop: '0.2rem' }}>
                      {rule.description}
                    </div>
                  </td>
                  <td style={{ padding: '0.85rem 1.25rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                      <input
                        type="number"
                        min="1"
                        max="100"
                        value={rule.weight}
                        onChange={(e) => handleUpdateWeight(rule.rule_id, e.target.value)}
                        style={{
                          width: '60px',
                          padding: '0.25rem 0.4rem',
                          borderRadius: 'var(--radius-sm)',
                          border: '1px solid var(--border)',
                          background: 'var(--bg-secondary)',
                          color: 'var(--text-primary)',
                          fontWeight: 600,
                          fontSize: '0.85rem',
                        }}
                      />
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)' }}>pts</span>
                    </div>
                  </td>
                  <td style={{ padding: '0.85rem 1.25rem' }}>
                    <label className="switch">
                      <input
                        type="checkbox"
                        checked={rule.enabled}
                        onChange={() => handleToggleRule(rule.rule_id)}
                      />
                      <span className="switch-slider" />
                    </label>
                  </td>
                  <td style={{ padding: '0.85rem 1.25rem', textAlign: 'right' }}>
                    <div style={{ display: 'flex', gap: '0.4rem', justifyContent: 'flex-end' }}>
                      <Button variant="ghost" size="sm" iconLeft={<FiEdit2 size={14} />} onClick={() => openEditModal(rule)}>
                        Edit
                      </Button>
                      <Button variant="ghost" size="sm" iconLeft={<FiTrash2 size={14} />} onClick={() => handleDeleteRule(rule.rule_id)}>
                        Delete
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Modal Form */}
      <Modal isOpen={modalOpen} onClose={() => setModalOpen(false)} title={editRule ? 'Edit Detection Rule' : 'Create Detection Rule'}>
        <form onSubmit={handleFormSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div>
            <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.25rem' }}>Rule ID</label>
            <input
              type="text"
              value={ruleId}
              onChange={(e) => setRuleId(e.target.value)}
              disabled={!!editRule}
              style={{ width: '100%', padding: '0.5rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text-primary)' }}
              required
            />
          </div>

          <div>
            <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.25rem' }}>Rule Name</label>
            <input
              type="text"
              value={ruleName}
              onChange={(e) => setRuleName(e.target.value)}
              style={{ width: '100%', padding: '0.5rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text-primary)' }}
              required
            />
          </div>

          <div>
            <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.25rem' }}>Description</label>
            <textarea
              rows={2}
              value={ruleDesc}
              onChange={(e) => setRuleDesc(e.target.value)}
              style={{ width: '100%', padding: '0.5rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text-primary)' }}
            />
          </div>

          <div>
            <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.25rem' }}>Risk Score Weight</label>
            <input
              type="number"
              min="1"
              max="100"
              value={ruleWeight}
              onChange={(e) => setRuleWeight(e.target.value)}
              style={{ width: '100%', padding: '0.5rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text-primary)' }}
              required
            />
          </div>

          <div>
            <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.25rem' }}>Rule Configuration (JSON)</label>
            <textarea
              rows={3}
              value={ruleConfigJson}
              onChange={(e) => setRuleConfigJson(e.target.value)}
              style={{ width: '100%', padding: '0.5rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text-primary)', fontFamily: 'monospace', fontSize: '0.8rem' }}
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.5rem' }}>
            <Button variant="ghost" onClick={() => setModalOpen(false)}>
              Cancel
            </Button>
            <Button variant="primary" type="submit">
              Save Rule
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
