// src/components/groups/GroupDetailModal.jsx
import React, { useState, useEffect } from 'react';
import Modal from '../ui/Modal';
import Button from '../ui/Button';
import Badge from '../ui/Badge';
import { useAgents } from '../../hooks/useAgents';
import {
  FiUsers,
  FiUserPlus,
  FiTrash2,
  FiServer,
  FiActivity,
  FiShield,
} from 'react-icons/fi';

export default function GroupDetailModal({
  isOpen,
  onClose,
  group,
  detail,
  loading = false,
  onAddMember,
  onRemoveMember,
}) {
  const { agents: allAgents } = useAgents();
  const [selectedAgentId, setSelectedAgentId] = useState('');
  const [adding, setAdding] = useState(false);
  const [removingId, setRemovingId] = useState(null);
  const [error, setError] = useState('');

  const members = detail?.members || [];
  const memberIds = new Set(members.map((m) => m.agent_id));
  const availableAgents = allAgents.filter((a) => !memberIds.has(a.id));

  useEffect(() => {
    setError('');
    setSelectedAgentId('');
  }, [isOpen, detail]);

  const handleAdd = async () => {
    if (!selectedAgentId) return;
    setError('');
    setAdding(true);
    try {
      if (onAddMember) {
        await onAddMember(group.id, [selectedAgentId]);
      }
      setSelectedAgentId('');
    } catch (err) {
      setError(err.message || 'Failed to add agent to group');
    } finally {
      setAdding(false);
    }
  };

  const handleRemove = async (agentId) => {
    if (!confirm(`Are you sure you want to remove agent '${agentId}' from group '${group?.name}'?`)) {
      return;
    }
    setError('');
    setRemovingId(agentId);
    try {
      if (onRemoveMember) {
        await onRemoveMember(group.id, agentId);
      }
    } catch (err) {
      setError(err.message || 'Failed to remove agent from group');
    } finally {
      setRemovingId(null);
    }
  };

  if (!group) return null;

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={`🏢 ${group.name} (${group.id})`}
      maxWidth={720}
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
        {/* Group Header Info */}
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            padding: '0.75rem 1rem',
            background: 'var(--bg-secondary, #f8fafc)',
            borderRadius: 'var(--radius-sm)',
            border: '1px solid var(--border)',
          }}
        >
          <div>
            <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
              {group.description || 'No description provided.'}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', marginTop: '0.2rem' }}>
              Created: {group.created_at ? new Date(group.created_at).toLocaleString() : 'N/A'}
            </div>
          </div>
          <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'center' }}>
            <Badge status="active" label="Normal Zone" />
            <span
              style={{
                fontSize: '0.75rem',
                fontWeight: 600,
                padding: '0.25rem 0.6rem',
                borderRadius: 'var(--radius-full)',
                background: 'var(--primary-light)',
                color: 'var(--primary)',
              }}
            >
              {members.length} {members.length === 1 ? 'member' : 'members'}
            </span>
          </div>
        </div>

        {/* Tab Navigation (Phase 1: 1 Tab Members) */}
        <div style={{ display: 'flex', borderBottom: '1px solid var(--border)' }}>
          <button
            type="button"
            className="filter-tab active"
            style={{
              padding: '0.5rem 1rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
              borderBottom: '2px solid var(--primary)',
              fontWeight: 600,
            }}
          >
            <FiUsers size={14} /> Group Members ({members.length})
          </button>
        </div>

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

        {/* Add Agent Bar */}
        <div
          style={{
            display: 'flex',
            gap: '0.5rem',
            alignItems: 'center',
            background: 'var(--bg-card)',
            padding: '0.75rem',
            borderRadius: 'var(--radius-sm)',
            border: '1px solid var(--border)',
          }}
        >
          <select
            className="search-input"
            style={{ flex: 1, padding: '0.45rem 0.75rem', fontSize: '0.85rem' }}
            value={selectedAgentId}
            onChange={(e) => setSelectedAgentId(e.target.value)}
            disabled={adding || loading}
          >
            <option value="">-- Select an agent to add to group --</option>
            {availableAgents.map((ag) => (
              <option key={ag.id} value={ag.id}>
                {ag.hostname || ag.id} ({ag.ip || ag.ip_address || 'No IP'})
              </option>
            ))}
          </select>
          <Button
            variant="primary"
            size="sm"
            onClick={handleAdd}
            disabled={!selectedAgentId || adding || loading}
          >
            <FiUserPlus size={13} style={{ marginRight: '0.3rem' }} />
            {adding ? 'Adding...' : 'Add Agent'}
          </Button>
        </div>

        {/* Members Table */}
        <div style={{ border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', overflow: 'hidden' }}>
          {loading ? (
            <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
              Loading members...
            </div>
          ) : members.length === 0 ? (
            <div style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
              <FiUsers size={32} style={{ marginBottom: '0.5rem', opacity: 0.5 }} />
              <div>No agents assigned to this group yet.</div>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-tertiary)', marginTop: '0.25rem' }}>
                Select an agent from the dropdown above to add them to {group.name}.
              </div>
            </div>
          ) : (
            <table className="table" style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ background: 'var(--bg-secondary, #f8fafc)', textAlign: 'left', fontSize: '0.775rem' }}>
                  <th style={{ padding: '0.65rem 0.85rem' }}>Agent ID</th>
                  <th style={{ padding: '0.65rem 0.85rem' }}>Hostname</th>
                  <th style={{ padding: '0.65rem 0.85rem' }}>IP Address</th>
                  <th style={{ padding: '0.65rem 0.85rem' }}>Status</th>
                  <th style={{ padding: '0.65rem 0.85rem' }}>Isolation</th>
                  <th style={{ padding: '0.65rem 0.85rem', textAlign: 'right' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {members.map((m) => (
                  <tr key={m.agent_id} style={{ borderTop: '1px solid var(--border)', fontSize: '0.825rem' }}>
                    <td style={{ padding: '0.65rem 0.85rem', fontFamily: 'monospace', fontWeight: 600 }}>
                      {m.agent_id}
                    </td>
                    <td style={{ padding: '0.65rem 0.85rem' }}>
                      {m.hostname || m.agent_id}
                    </td>
                    <td style={{ padding: '0.65rem 0.85rem', color: 'var(--text-secondary)' }}>
                      {m.ip_address || '—'}
                    </td>
                    <td style={{ padding: '0.65rem 0.85rem' }}>
                      <Badge status={m.status || 'active'} />
                    </td>
                    <td style={{ padding: '0.65rem 0.85rem' }}>
                      {m.is_isolated ? (
                        <span style={{ color: 'var(--error)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                          <FiShield size={12} /> Isolated
                        </span>
                      ) : (
                        <span style={{ color: 'var(--success)', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                          <FiActivity size={12} /> Normal
                        </span>
                      )}
                    </td>
                    <td style={{ padding: '0.65rem 0.85rem', textAlign: 'right' }}>
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm"
                        style={{ color: 'var(--error)', padding: '0.2rem 0.4rem', fontSize: '0.75rem' }}
                        onClick={() => handleRemove(m.agent_id)}
                        disabled={removingId === m.agent_id}
                        title="Remove from group"
                      >
                        <FiTrash2 size={13} /> {removingId === m.agent_id ? 'Removing...' : 'Remove'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Footer */}
        <div style={{ display: 'flex', justifyContent: 'flex-end', paddingTop: '0.5rem' }}>
          <Button variant="secondary" onClick={onClose}>
            Close
          </Button>
        </div>
      </div>
    </Modal>
  );
}
