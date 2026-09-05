// src/components/rules/ProcessChainRulesTab.jsx
import React, { useState, useMemo } from 'react';
import Modal from '../ui/Modal';
import Button from '../ui/Button';
import Badge from '../ui/Badge';
import SearchBar from '../ui/SearchBar';
import {
  FiPlus,
  FiEdit2,
  FiTrash2,
  FiRotateCw,
  FiShield,
  FiAlertTriangle,
  FiArrowRight,
  FiCheckCircle,
  FiXCircle,
  FiInfo,
} from 'react-icons/fi';

const ACTION_OPTIONS = [
  { value: 'alert', label: 'Alert (Warning Notification)', badgeStatus: 'warning' },
  { value: 'block', label: 'Block (Terminate Process)', badgeStatus: 'critical' },
  { value: 'isolate', label: 'Isolate (Network Containment)', badgeStatus: 'critical' },
];

export default function ProcessChainRulesTab({
  chainRules,
  groups,
  loading,
  error,
  refreshChainRules,
  handleToggleActive,
  handleCreateChainRule,
  handleUpdateChainRule,
  handleDeleteChainRule,
  onSwitchToGroupsTab,
  onNotice,
}) {
  const [search, setSearch] = useState('');
  const [modalOpen, setModalOpen] = useState(false);
  const [editingRule, setEditingRule] = useState(null);

  // Form State
  const [name, setName] = useState('');
  const [parentGroupId, setParentGroupId] = useState('');
  const [childGroupId, setChildGroupId] = useState('');
  const [action, setAction] = useState('alert');
  const [isActive, setIsActive] = useState(true);
  const [formError, setFormError] = useState('');
  const [saving, setSaving] = useState(false);

  const filteredRules = useMemo(() => {
    if (!search.trim()) return chainRules;
    const term = search.toLowerCase();
    return chainRules.filter((r) => {
      const pName = r.parent_group?.name || '';
      const cName = r.child_group?.name || '';
      return (
        r.name.toLowerCase().includes(term) ||
        pName.toLowerCase().includes(term) ||
        cName.toLowerCase().includes(term) ||
        r.action.toLowerCase().includes(term)
      );
    });
  }, [chainRules, search]);

  const openCreateModal = () => {
    if (groups.length === 0) {
      setFormError('No process groups found. Please create at least one Process Group first.');
      setModalOpen(true);
      return;
    }
    setEditingRule(null);
    setName('');
    setParentGroupId(groups[0]?.id || '');
    setChildGroupId(groups[1]?.id || groups[0]?.id || '');
    setAction('alert');
    setIsActive(true);
    setFormError('');
    setModalOpen(true);
  };

  const openEditModal = (rule) => {
    setEditingRule(rule);
    setName(rule.name);
    setParentGroupId(rule.parent_group_id);
    setChildGroupId(rule.child_group_id);
    setAction(rule.action || 'alert');
    setIsActive(rule.is_active !== undefined ? rule.is_active : true);
    setFormError('');
    setModalOpen(true);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!name.trim()) {
      setFormError('Rule name is required.');
      return;
    }
    if (!parentGroupId) {
      setFormError('Parent Process Group must be selected.');
      return;
    }
    if (!childGroupId) {
      setFormError('Child Process Group must be selected.');
      return;
    }

    setSaving(true);
    setFormError('');
    try {
      const payload = {
        name: name.trim(),
        parent_group_id: parentGroupId,
        child_group_id: childGroupId,
        action,
        is_active: isActive,
      };

      if (editingRule) {
        await handleUpdateChainRule(editingRule.id, payload);
        onNotice?.(`Updated process chain rule '${payload.name}'`);
      } else {
        await handleCreateChainRule(payload);
        onNotice?.(`Created process chain rule '${payload.name}'`);
      }
      setModalOpen(false);
    } catch (err) {
      setFormError(err.message || 'Failed to save process chain rule.');
    } finally {
      setSaving(false);
    }
  };

  const onToggle = async (rule) => {
    try {
      await handleToggleActive(rule.id);
      onNotice?.(`Rule '${rule.name}' is now ${!rule.is_active ? 'active' : 'disabled'}`);
    } catch (err) {
      onNotice?.(`Failed to toggle rule: ${err.message}`, true);
    }
  };

  const onDelete = async (rule) => {
    if (window.confirm(`Are you sure you want to delete rule '${rule.name}'?`)) {
      try {
        await handleDeleteChainRule(rule.id);
        onNotice?.(`Deleted rule '${rule.name}'`);
      } catch (err) {
        onNotice?.(`Failed to delete rule: ${err.message}`, true);
      }
    }
  };

  const getActionBadge = (act) => {
    const a = (act || 'alert').toLowerCase();
    if (a === 'isolate') return <Badge status="critical" label="ISOLATE" showDot={true} />;
    if (a === 'block') return <Badge status="critical" label="BLOCK" showDot={true} />;
    return <Badge status="warning" label="ALERT" showDot={true} />;
  };

  return (
    <div>
      {/* Warning banner when no groups exist */}
      {groups.length === 0 && !loading && (
        <div
          style={{
            marginBottom: '1rem',
            padding: '0.85rem 1.15rem',
            borderRadius: 'var(--radius-md, 6px)',
            background: 'rgba(234, 179, 8, 0.12)',
            border: '1px solid rgba(234, 179, 8, 0.35)',
            color: '#eab308',
            fontSize: '0.875rem',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '1rem',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <FiInfo size={18} />
            <span>
              <strong>Notice:</strong> No process groups currently exist. Please define Process Groups
              before setting up parent-child detection rules.
            </span>
          </div>
          {onSwitchToGroupsTab && (
            <Button size="sm" variant="outline" onClick={onSwitchToGroupsTab}>
              Go to Process Groups
            </Button>
          )}
        </div>
      )}

      {/* Action bar */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: '1rem',
          marginBottom: '1rem',
          flexWrap: 'wrap',
        }}
      >
        <div style={{ flex: 1, minWidth: '240px', maxWidth: '400px' }}>
          <SearchBar
            value={search}
            onChange={setSearch}
            placeholder="Search rules by name, group, action..."
          />
        </div>
        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <Button variant="outline" iconLeft={<FiRotateCw size={15} />} onClick={refreshChainRules}>
            Refresh
          </Button>
          <Button variant="primary" iconLeft={<FiPlus size={15} />} onClick={openCreateModal}>
            Add Chain Rule
          </Button>
        </div>
      </div>

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
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
          }}
        >
          <FiAlertTriangle size={16} />
          {error}
        </div>
      )}

      {/* Rules Table */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ overflowX: 'auto' }}>
          <table
            style={{
              width: '100%',
              borderCollapse: 'collapse',
              textAlign: 'left',
              fontSize: '0.875rem',
            }}
          >
            <thead>
              <tr
                style={{
                  background: 'var(--bg-secondary)',
                  borderBottom: '1px solid var(--border)',
                  color: 'var(--text-secondary)',
                }}
              >
                <th style={{ padding: '0.85rem 1.25rem', width: '25%' }}>Rule Name</th>
                <th style={{ padding: '0.85rem 1.25rem', width: '35%' }}>Process Relationship</th>
                <th style={{ padding: '0.85rem 1.25rem', width: '15%' }}>Action</th>
                <th style={{ padding: '0.85rem 1.25rem', width: '13%' }}>Status</th>
                <th style={{ padding: '0.85rem 1.25rem', width: '12%', textAlign: 'right' }}>
                  Actions
                </th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={5} style={{ padding: '3rem', textAlign: 'center' }}>
                    <div className="card skeleton" style={{ height: '80px', margin: '0 auto' }} />
                  </td>
                </tr>
              ) : filteredRules.length === 0 ? (
                <tr>
                  <td
                    colSpan={5}
                    style={{
                      padding: '3rem',
                      textAlign: 'center',
                      color: 'var(--text-tertiary)',
                    }}
                  >
                    <FiShield size={32} style={{ margin: '0 auto 0.5rem', opacity: 0.5 }} />
                    <p>No process chain rules configured.</p>
                  </td>
                </tr>
              ) : (
                filteredRules.map((rule) => (
                  <tr
                    key={rule.id}
                    style={{
                      borderBottom: '1px solid var(--border)',
                      opacity: rule.is_active ? 1 : 0.65,
                      transition: 'background-color 0.15s ease',
                    }}
                  >
                    <td style={{ padding: '0.85rem 1.25rem' }}>
                      <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                        {rule.name}
                      </div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)' }}>
                        ID: {rule.id.slice(0, 8)}...
                      </div>
                    </td>
                    <td style={{ padding: '0.85rem 1.25rem' }}>
                      <div
                        style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '0.5rem',
                          background: 'var(--bg-secondary)',
                          padding: '0.35rem 0.65rem',
                          borderRadius: 'var(--radius-sm, 4px)',
                          border: '1px solid var(--border)',
                          fontSize: '0.825rem',
                        }}
                      >
                        <span style={{ fontWeight: 600, color: 'var(--primary)' }}>
                          {rule.parent_group?.name || 'Unknown Parent'}
                        </span>
                        <FiArrowRight size={13} color="var(--text-tertiary)" />
                        <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                          {rule.child_group?.name || 'Unknown Child'}
                        </span>
                      </div>
                    </td>
                    <td style={{ padding: '0.85rem 1.25rem' }}>
                      {getActionBadge(rule.action)}
                    </td>
                    <td style={{ padding: '0.85rem 1.25rem' }}>
                      <label
                        style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '0.45rem',
                          cursor: 'pointer',
                          userSelect: 'none',
                        }}
                      >
                        <input
                          type="checkbox"
                          checked={rule.is_active}
                          onChange={() => onToggle(rule)}
                          style={{
                            cursor: 'pointer',
                            accentColor: 'var(--primary)',
                            width: '16px',
                            height: '16px',
                          }}
                        />
                        <span
                          style={{
                            fontSize: '0.8rem',
                            fontWeight: 600,
                            color: rule.is_active ? 'var(--success)' : 'var(--text-tertiary)',
                          }}
                        >
                          {rule.is_active ? 'Active' : 'Disabled'}
                        </span>
                      </label>
                    </td>
                    <td style={{ padding: '0.85rem 1.25rem', textAlign: 'right' }}>
                      <div
                        style={{
                          display: 'flex',
                          justifyContent: 'flex-end',
                          gap: '0.5rem',
                        }}
                      >
                        <Button
                          variant="outline"
                          size="sm"
                          iconLeft={<FiEdit2 size={13} />}
                          onClick={() => openEditModal(rule)}
                          title="Edit Rule"
                        >
                          Edit
                        </Button>
                        <Button
                          variant="danger"
                          size="sm"
                          iconLeft={<FiTrash2 size={13} />}
                          onClick={() => onDelete(rule)}
                          title="Delete Rule"
                        >
                          Delete
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Modal Add/Edit Rule */}
      <Modal
        isOpen={modalOpen}
        onClose={() => setModalOpen(false)}
        title={editingRule ? 'Edit Process Chain Rule' : 'Create Process Chain Rule'}
        maxWidth={560}
      >
        {groups.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '1rem 0' }}>
            <FiAlertTriangle size={36} color="#eab308" style={{ marginBottom: '0.75rem' }} />
            <h4 style={{ marginBottom: '0.5rem' }}>No Process Groups Available</h4>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', marginBottom: '1.25rem' }}>
              Process chain rules require existing Process Groups for both Parent and Child entities.
            </p>
            <Button
              variant="primary"
              onClick={() => {
                setModalOpen(false);
                onSwitchToGroupsTab?.();
              }}
            >
              Create a Process Group
            </Button>
          </div>
        ) : (
          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1.15rem' }}>
            {formError && (
              <div
                style={{
                  padding: '0.75rem 1rem',
                  borderRadius: 'var(--radius-md)',
                  background: 'rgba(239, 68, 68, 0.15)',
                  border: '1px solid var(--error)',
                  color: 'var(--error)',
                  fontSize: '0.85rem',
                }}
              >
                {formError}
              </div>
            )}

            <div>
              <label
                style={{
                  display: 'block',
                  fontWeight: 600,
                  fontSize: '0.85rem',
                  marginBottom: '0.4rem',
                  color: 'var(--text-primary)',
                }}
              >
                Rule Name *
              </label>
              <input
                type="text"
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. Office Spawning Command Shell"
                style={{
                  width: '100%',
                  padding: '0.6rem 0.85rem',
                  borderRadius: 'var(--radius-md, 6px)',
                  border: '1px solid var(--border)',
                  background: 'var(--bg-secondary)',
                  color: 'var(--text-primary)',
                  fontSize: '0.875rem',
                }}
              />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
              <div>
                <label
                  style={{
                    display: 'block',
                    fontWeight: 600,
                    fontSize: '0.85rem',
                    marginBottom: '0.4rem',
                    color: 'var(--text-primary)',
                  }}
                >
                  Parent Process Group *
                </label>
                <select
                  value={parentGroupId}
                  onChange={(e) => setParentGroupId(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '0.6rem 0.85rem',
                    borderRadius: 'var(--radius-md, 6px)',
                    border: '1px solid var(--border)',
                    background: 'var(--bg-secondary)',
                    color: 'var(--text-primary)',
                    fontSize: '0.875rem',
                  }}
                >
                  {groups.map((g) => (
                    <option key={g.id} value={g.id}>
                      {g.name} ({g.patterns?.length || 0} patterns)
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label
                  style={{
                    display: 'block',
                    fontWeight: 600,
                    fontSize: '0.85rem',
                    marginBottom: '0.4rem',
                    color: 'var(--text-primary)',
                  }}
                >
                  Child Process Group *
                </label>
                <select
                  value={childGroupId}
                  onChange={(e) => setChildGroupId(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '0.6rem 0.85rem',
                    borderRadius: 'var(--radius-md, 6px)',
                    border: '1px solid var(--border)',
                    background: 'var(--bg-secondary)',
                    color: 'var(--text-primary)',
                    fontSize: '0.875rem',
                  }}
                >
                  {groups.map((g) => (
                    <option key={g.id} value={g.id}>
                      {g.name} ({g.patterns?.length || 0} patterns)
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div>
              <label
                style={{
                  display: 'block',
                  fontWeight: 600,
                  fontSize: '0.85rem',
                  marginBottom: '0.4rem',
                  color: 'var(--text-primary)',
                }}
              >
                Response Action *
              </label>
              <select
                value={action}
                onChange={(e) => setAction(e.target.value)}
                style={{
                  width: '100%',
                  padding: '0.6rem 0.85rem',
                  borderRadius: 'var(--radius-md, 6px)',
                  border: '1px solid var(--border)',
                  background: 'var(--bg-secondary)',
                  color: 'var(--text-primary)',
                  fontSize: '0.875rem',
                }}
              >
                {ACTION_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  cursor: 'pointer',
                  userSelect: 'none',
                }}
              >
                <input
                  type="checkbox"
                  checked={isActive}
                  onChange={(e) => setIsActive(e.target.checked)}
                  style={{
                    cursor: 'pointer',
                    accentColor: 'var(--primary)',
                    width: '16px',
                    height: '16px',
                  }}
                />
                <span style={{ fontWeight: 600, fontSize: '0.85rem', color: 'var(--text-primary)' }}>
                  Enable this rule immediately
                </span>
              </label>
            </div>

            <div
              style={{
                display: 'flex',
                justifyContent: 'flex-end',
                gap: '0.75rem',
                marginTop: '0.5rem',
              }}
            >
              <Button
                type="button"
                variant="outline"
                onClick={() => setModalOpen(false)}
                disabled={saving}
              >
                Cancel
              </Button>
              <Button type="submit" variant="primary" disabled={saving}>
                {saving ? 'Saving...' : editingRule ? 'Update Rule' : 'Create Rule'}
              </Button>
            </div>
          </form>
        )}
      </Modal>
    </div>
  );
}
