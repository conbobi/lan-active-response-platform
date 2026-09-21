// src/components/groups/CreateGroupModal.jsx
import React, { useState, useEffect } from 'react';
import Modal from '../ui/Modal';
import Button from '../ui/Button';

export default function CreateGroupModal({
  isOpen,
  onClose,
  onCreated,
  editGroup = null,
}) {
  const [groupId, setGroupId] = useState('');
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const isEdit = !!editGroup;

  useEffect(() => {
    if (editGroup) {
      setGroupId(editGroup.id || '');
      setName(editGroup.name || '');
      setDescription(editGroup.description || '');
    } else {
      setGroupId('');
      setName('');
      setDescription('');
    }
    setError('');
  }, [editGroup, isOpen]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    const trimmedName = name.trim();
    if (!trimmedName) {
      setError('Group name is required.');
      return;
    }

    const payload = {
      name: trimmedName,
      description: description.trim() || undefined,
    };

    if (!isEdit && groupId.trim()) {
      const cleanId = groupId.trim();
      if (!/^[a-z0-9_-]+$/.test(cleanId)) {
        setError('Group ID must contain only lowercase letters, numbers, hyphens, and underscores.');
        return;
      }
      payload.id = cleanId;
    }

    setLoading(true);
    try {
      if (onCreated) {
        await onCreated(payload, editGroup?.id);
      }
      onClose();
    } catch (err) {
      setError(err.message || 'Failed to save agent group.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={isEdit ? `Edit Group: ${editGroup?.name}` : 'Create New Agent Group'}
      maxWidth={520}
    >
      <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        {error && (
          <div
            style={{
              padding: '0.65rem 0.85rem',
              borderRadius: 'var(--radius-sm)',
              background: 'rgba(239, 68, 68, 0.1)',
              border: '1px solid var(--error)',
              color: 'var(--error)',
              fontSize: '0.825rem',
            }}
          >
            {error}
          </div>
        )}

        {!isEdit && (
          <div>
            <label
              style={{
                display: 'block',
                fontSize: '0.8rem',
                fontWeight: 600,
                color: 'var(--text-primary)',
                marginBottom: '0.35rem',
              }}
            >
              Group ID <span style={{ color: 'var(--text-tertiary)', fontWeight: 400 }}>(Optional, e.g. grp_sales)</span>
            </label>
            <input
              type="text"
              className="search-input"
              style={{ width: '100%', padding: '0.5rem 0.75rem' }}
              placeholder="e.g. grp_sales or sales"
              value={groupId}
              onChange={(e) => setGroupId(e.target.value.toLowerCase())}
              disabled={loading}
            />
            <span style={{ fontSize: '0.725rem', color: 'var(--text-tertiary)', marginTop: '0.2rem', display: 'block' }}>
              Leave blank to automatically generate a unique ID.
            </span>
          </div>
        )}

        <div>
          <label
            style={{
              display: 'block',
              fontSize: '0.8rem',
              fontWeight: 600,
              color: 'var(--text-primary)',
              marginBottom: '0.35rem',
            }}
          >
            Group Name <span style={{ color: 'var(--error)' }}>*</span>
          </label>
          <input
            type="text"
            className="search-input"
            style={{ width: '100%', padding: '0.5rem 0.75rem' }}
            placeholder="e.g. Sales Department, Core Servers"
            value={name}
            onChange={(e) => setName(e.target.value)}
            disabled={loading}
            required
          />
        </div>

        <div>
          <label
            style={{
              display: 'block',
              fontSize: '0.8rem',
              fontWeight: 600,
              color: 'var(--text-primary)',
              marginBottom: '0.35rem',
            }}
          >
            Description
          </label>
          <textarea
            className="search-input"
            style={{ width: '100%', padding: '0.5rem 0.75rem', minHeight: '80px', resize: 'vertical' }}
            placeholder="Describe the department, subnet, or responsibilities of this group..."
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            disabled={loading}
          />
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.5rem' }}>
          <Button variant="ghost" onClick={onClose} disabled={loading}>
            Cancel
          </Button>
          <Button variant="primary" type="submit" disabled={loading}>
            {loading ? 'Saving...' : isEdit ? 'Update Group' : 'Create Group'}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
