// src/components/rules/ProcessGroupsTab.jsx
import React, { useState, useMemo } from 'react';
import Modal from '../ui/Modal';
import Button from '../ui/Button';
import SearchBar from '../ui/SearchBar';
import {
  FiPlus,
  FiEdit2,
  FiTrash2,
  FiRotateCw,
  FiFolder,
  FiX,
  FiTag,
  FiAlertCircle,
} from 'react-icons/fi';

export default function ProcessGroupsTab({
  groups,
  loading,
  error,
  refreshGroups,
  handleCreateGroup,
  handleUpdateGroup,
  handleDeleteGroup,
  onNotice,
}) {
  const [search, setSearch] = useState('');
  const [modalOpen, setModalOpen] = useState(false);
  const [editingGroup, setEditingGroup] = useState(null);

  // Form State
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [patterns, setPatterns] = useState([]);
  const [patternInput, setPatternInput] = useState('');
  const [formError, setFormError] = useState('');
  const [saving, setSaving] = useState(false);

  const filteredGroups = useMemo(() => {
    if (!search.trim()) return groups;
    const term = search.toLowerCase();
    return groups.filter(
      (g) =>
        g.name.toLowerCase().includes(term) ||
        (g.description && g.description.toLowerCase().includes(term)) ||
        (g.patterns && g.patterns.some((p) => p.toLowerCase().includes(term)))
    );
  }, [groups, search]);

  const openCreateModal = () => {
    setEditingGroup(null);
    setName('');
    setDescription('');
    setPatterns([]);
    setPatternInput('');
    setFormError('');
    setModalOpen(true);
  };

  const openEditModal = (group) => {
    setEditingGroup(group);
    setName(group.name);
    setDescription(group.description || '');
    setPatterns(Array.isArray(group.patterns) ? [...group.patterns] : []);
    setPatternInput('');
    setFormError('');
    setModalOpen(true);
  };

  const handleAddPattern = () => {
    const raw = patternInput.trim();
    if (!raw) return;

    // Support comma or space separated multiple values
    const parts = raw
      .split(/[,\s]+/)
      .map((p) => p.trim().toLowerCase())
      .filter((p) => p && !patterns.includes(p));

    if (parts.length === 0 && patterns.includes(raw.toLowerCase())) {
      setFormError(`Pattern '${raw}' is already added.`);
      return;
    }

    setPatterns((prev) => [...prev, ...parts]);
    setPatternInput('');
    setFormError('');
  };

  const handleKeyDownPattern = (e) => {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault();
      handleAddPattern();
    }
  };

  const handleRemovePattern = (idx) => {
    setPatterns((prev) => prev.filter((_, i) => i !== idx));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!name.trim()) {
      setFormError('Group name is required.');
      return;
    }
    if (patterns.length === 0) {
      setFormError('Please provide at least one process pattern.');
      return;
    }

    setSaving(true);
    setFormError('');
    try {
      const payload = {
        name: name.trim(),
        description: description.trim(),
        patterns,
      };

      if (editingGroup) {
        await handleUpdateGroup(editingGroup.id, payload);
        onNotice?.(`Updated process group '${payload.name}' successfully!`);
      } else {
        await handleCreateGroup(payload);
        onNotice?.(`Created process group '${payload.name}' successfully!`);
      }
      setModalOpen(false);
    } catch (err) {
      setFormError(err.message || 'Failed to save process group.');
    } finally {
      setSaving(false);
    }
  };

  const onDelete = async (group) => {
    if (window.confirm(`Are you sure you want to delete process group '${group.name}'?`)) {
      try {
        await handleDeleteGroup(group.id);
        onNotice?.(`Deleted process group '${group.name}'`);
      } catch (err) {
        // Specifically handle 409 conflict
        const msg = err.message || '';
        if (msg.includes('409') || msg.includes('referenced') || msg.includes('rule')) {
          onNotice?.(
            `Cannot delete '${group.name}': It is currently referenced by active Process Chain Rules. Please remove or update the rules first.`,
            true
          );
        } else {
          onNotice?.(`Failed to delete process group: ${msg}`, true);
        }
      }
    }
  };

  return (
    <div>
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
            placeholder="Search groups by name, description, patterns..."
          />
        </div>
        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <Button variant="outline" iconLeft={<FiRotateCw size={15} />} onClick={refreshGroups}>
            Refresh
          </Button>
          <Button variant="primary" iconLeft={<FiPlus size={15} />} onClick={openCreateModal}>
            Add Process Group
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
          <FiAlertCircle size={16} />
          {error}
        </div>
      )}

      {/* Table */}
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
                <th style={{ padding: '0.85rem 1.25rem', width: '22%' }}>Group Name</th>
                <th style={{ padding: '0.85rem 1.25rem', width: '40%' }}>Patterns</th>
                <th style={{ padding: '0.85rem 1.25rem', width: '26%' }}>Description</th>
                <th style={{ padding: '0.85rem 1.25rem', width: '12%', textAlign: 'right' }}>
                  Actions
                </th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={4} style={{ padding: '3rem', textAlign: 'center' }}>
                    <div className="card skeleton" style={{ height: '80px', margin: '0 auto' }} />
                  </td>
                </tr>
              ) : filteredGroups.length === 0 ? (
                <tr>
                  <td
                    colSpan={4}
                    style={{
                      padding: '3rem',
                      textAlign: 'center',
                      color: 'var(--text-tertiary)',
                    }}
                  >
                    <FiFolder size={32} style={{ margin: '0 auto 0.5rem', opacity: 0.5 }} />
                    <p>No process groups found.</p>
                  </td>
                </tr>
              ) : (
                filteredGroups.map((group) => (
                  <tr
                    key={group.id}
                    style={{
                      borderBottom: '1px solid var(--border)',
                      transition: 'background-color 0.15s ease',
                    }}
                  >
                    <td style={{ padding: '0.85rem 1.25rem' }}>
                      <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                        {group.name}
                      </div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)' }}>
                        ID: {group.id.slice(0, 8)}...
                      </div>
                    </td>
                    <td style={{ padding: '0.85rem 1.25rem' }}>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
                        {group.patterns && group.patterns.length > 0 ? (
                          group.patterns.map((pat, idx) => (
                            <span
                              key={idx}
                              style={{
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '0.25rem',
                                padding: '0.2rem 0.55rem',
                                borderRadius: 'var(--radius-sm, 4px)',
                                background: 'rgba(59, 130, 246, 0.12)',
                                border: '1px solid rgba(59, 130, 246, 0.25)',
                                color: 'var(--primary, #3b82f6)',
                                fontSize: '0.775rem',
                                fontFamily: 'monospace',
                                fontWeight: 600,
                              }}
                            >
                              <FiTag size={11} opacity={0.7} />
                              {pat}
                            </span>
                          ))
                        ) : (
                          <span style={{ color: 'var(--text-tertiary)', fontSize: '0.8rem' }}>
                            No patterns
                          </span>
                        )}
                      </div>
                    </td>
                    <td
                      style={{
                        padding: '0.85rem 1.25rem',
                        color: 'var(--text-secondary)',
                        fontSize: '0.825rem',
                      }}
                    >
                      {group.description || '—'}
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
                          onClick={() => openEditModal(group)}
                          title="Edit Group"
                        >
                          Edit
                        </Button>
                        <Button
                          variant="danger"
                          size="sm"
                          iconLeft={<FiTrash2 size={13} />}
                          onClick={() => onDelete(group)}
                          title="Delete Group"
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

      {/* Modal Add/Edit Group */}
      <Modal
        isOpen={modalOpen}
        onClose={() => setModalOpen(false)}
        title={editingGroup ? 'Edit Process Group' : 'Create Process Group'}
        maxWidth={540}
      >
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
              Group Name *
            </label>
            <input
              type="text"
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Office Applications, Command Shells"
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
              Description
            </label>
            <textarea
              rows={2}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Optional summary of this process group..."
              style={{
                width: '100%',
                padding: '0.6rem 0.85rem',
                borderRadius: 'var(--radius-md, 6px)',
                border: '1px solid var(--border)',
                background: 'var(--bg-secondary)',
                color: 'var(--text-primary)',
                fontSize: '0.875rem',
                resize: 'vertical',
              }}
            />
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
              Process Patterns * (e.g. winword.exe, cmd.exe, bash)
            </label>
            <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.6rem' }}>
              <input
                type="text"
                value={patternInput}
                onChange={(e) => setPatternInput(e.target.value)}
                onKeyDown={handleKeyDownPattern}
                placeholder="Type process name (e.g. powershell.exe) & press Enter"
                style={{
                  flex: 1,
                  padding: '0.6rem 0.85rem',
                  borderRadius: 'var(--radius-md, 6px)',
                  border: '1px solid var(--border)',
                  background: 'var(--bg-secondary)',
                  color: 'var(--text-primary)',
                  fontSize: '0.875rem',
                }}
              />
              <Button type="button" variant="outline" onClick={handleAddPattern}>
                Add
              </Button>
            </div>

            {/* Render Tags */}
            <div
              style={{
                display: 'flex',
                flexWrap: 'wrap',
                gap: '0.4rem',
                padding: '0.65rem',
                background: 'var(--bg-secondary)',
                border: '1px dashed var(--border)',
                borderRadius: 'var(--radius-md, 6px)',
                minHeight: '48px',
                alignItems: 'center',
              }}
            >
              {patterns.length === 0 ? (
                <span style={{ fontSize: '0.8rem', color: 'var(--text-tertiary)' }}>
                  No patterns added yet. Add at least one pattern above.
                </span>
              ) : (
                patterns.map((pat, idx) => (
                  <span
                    key={idx}
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '0.35rem',
                      padding: '0.25rem 0.6rem',
                      borderRadius: 'var(--radius-sm, 4px)',
                      background: 'var(--bg-primary)',
                      border: '1px solid var(--border)',
                      color: 'var(--text-primary)',
                      fontSize: '0.8rem',
                      fontFamily: 'monospace',
                    }}
                  >
                    <span>{pat}</span>
                    <button
                      type="button"
                      onClick={() => handleRemovePattern(idx)}
                      style={{
                        background: 'transparent',
                        border: 'none',
                        cursor: 'pointer',
                        padding: 0,
                        display: 'inline-flex',
                        alignItems: 'center',
                        color: 'var(--text-tertiary)',
                      }}
                      title="Remove pattern"
                    >
                      <FiX size={13} />
                    </button>
                  </span>
                ))
              )}
            </div>
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
              {saving ? 'Saving...' : editingGroup ? 'Update Group' : 'Create Group'}
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
