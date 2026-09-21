// src/components/groups/AddAgentDropdown.jsx
import React, { useState, useRef, useEffect, useMemo } from 'react';
import { useAgents } from '../../hooks/useAgents';
import { addAgentToGroup } from '../../api/groups';
import Button from '../ui/Button';
import Badge from '../ui/Badge';
import {
  FiUserPlus,
  FiSearch,
  FiServer,
  FiCheck,
  FiX,
  FiChevronDown,
  FiLoader,
} from 'react-icons/fi';

export default function AddAgentDropdown({
  groupId,
  currentMembers = [],
  onAdded,
}) {
  const { agents: allAgents, loading: agentsLoading } = useAgents();
  const [isOpen, setIsOpen] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [addingId, setAddingId] = useState(null);
  const [error, setError] = useState('');
  const dropdownRef = useRef(null);

  // Close dropdown on click outside
  useEffect(() => {
    const handleClickOutside = (e) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
        setIsOpen(false);
      }
    };
    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [isOpen]);

  // Existing member IDs
  const memberIds = useMemo(() => {
    return new Set(currentMembers.map((m) => m.agent_id || m.id));
  }, [currentMembers]);

  // Available agents not yet in group
  const availableAgents = useMemo(() => {
    return allAgents.filter((agent) => !memberIds.has(agent.id));
  }, [allAgents, memberIds]);

  // Filtered by search query
  const filteredAgents = useMemo(() => {
    if (!searchTerm.trim()) return availableAgents;
    const query = searchTerm.toLowerCase();
    return availableAgents.filter((agent) => {
      const matchId = agent.id.toLowerCase().includes(query);
      const matchHost = (agent.hostname || '').toLowerCase().includes(query);
      const matchIp = (agent.ip || agent.ip_address || '').toLowerCase().includes(query);
      return matchId || matchHost || matchIp;
    });
  }, [availableAgents, searchTerm]);

  const handleSelectAgent = async (agent) => {
    if (addingId) return;
    setError('');
    setAddingId(agent.id);
    try {
      await addAgentToGroup(groupId, [agent.id]);
      setIsOpen(false);
      setSearchTerm('');
      if (onAdded) {
        await onAdded(agent);
      }
    } catch (err) {
      console.error(`Failed to add agent ${agent.id} to group ${groupId}`, err);
      setError(err.response?.data?.detail || err.message || 'Failed to add agent');
    } finally {
      setAddingId(null);
    }
  };

  return (
    <div ref={dropdownRef} style={{ position: 'relative', display: 'inline-block' }}>
      <Button
        variant="primary"
        size="sm"
        onClick={() => {
          setIsOpen(!isOpen);
          setError('');
          setSearchTerm('');
        }}
        iconLeft={<FiUserPlus size={14} />}
        iconRight={<FiChevronDown size={13} style={{ transform: isOpen ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s' }} />}
      >
        Add Agent to Group
      </Button>

      {isOpen && (
        <div
          style={{
            position: 'absolute',
            top: 'calc(100% + 6px)',
            right: 0,
            zIndex: 1000,
            width: '340px',
            background: 'var(--bg-card, #ffffff)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius-sm, 6px)',
            boxShadow: 'var(--shadow-lg, 0 10px 25px -5px rgba(0, 0, 0, 0.2))',
            overflow: 'hidden',
            display: 'flex',
            flexDirection: 'column',
          }}
        >
          {/* Search Header */}
          <div
            style={{
              padding: '0.65rem 0.75rem',
              borderBottom: '1px solid var(--border)',
              background: 'var(--bg-secondary, #f8fafc)',
            }}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
                background: 'var(--bg-primary, #ffffff)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius-xs, 4px)',
                padding: '0.35rem 0.6rem',
              }}
            >
              <FiSearch size={14} color="var(--text-tertiary)" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search agent ID, host, IP..."
                autoFocus
                style={{
                  border: 'none',
                  outline: 'none',
                  background: 'transparent',
                  fontSize: '0.8rem',
                  color: 'var(--text-primary)',
                  width: '100%',
                }}
              />
              {searchTerm && (
                <button
                  type="button"
                  onClick={() => setSearchTerm('')}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0, display: 'flex' }}
                >
                  <FiX size={13} color="var(--text-tertiary)" />
                </button>
              )}
            </div>
            {error && (
              <div style={{ color: 'var(--error, #ef4444)', fontSize: '0.75rem', marginTop: '0.4rem' }}>
                {error}
              </div>
            )}
          </div>

          {/* List of unassigned agents */}
          <div style={{ maxHeight: '250px', overflowY: 'auto' }}>
            {agentsLoading ? (
              <div style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--text-tertiary)', fontSize: '0.8rem' }}>
                <FiLoader size={18} className="animate-spin" style={{ display: 'inline-block', marginBottom: '0.3rem' }} />
                <div>Loading agents...</div>
              </div>
            ) : availableAgents.length === 0 ? (
              <div style={{ padding: '1.5rem 1rem', textAlign: 'center', color: 'var(--text-tertiary)', fontSize: '0.8rem' }}>
                <FiCheck size={20} color="var(--success, #10b981)" style={{ display: 'inline-block', marginBottom: '0.3rem' }} />
                <div>Tất cả agents đã có trong nhóm.</div>
              </div>
            ) : filteredAgents.length === 0 ? (
              <div style={{ padding: '1.5rem 1rem', textAlign: 'center', color: 'var(--text-tertiary)', fontSize: '0.8rem' }}>
                Không tìm thấy agent phù hợp với "{searchTerm}".
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column' }}>
                {filteredAgents.map((agent) => {
                  const isAdding = addingId === agent.id;
                  const isOnline = agent.status === 'online';
                  return (
                    <button
                      key={agent.id}
                      type="button"
                      disabled={!!addingId}
                      onClick={() => handleSelectAgent(agent)}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '0.65rem 0.85rem',
                        border: 'none',
                        borderBottom: '1px solid var(--border)',
                        background: 'transparent',
                        cursor: addingId ? 'not-allowed' : 'pointer',
                        textAlign: 'left',
                        transition: 'background 0.15s',
                        width: '100%',
                      }}
                      onMouseEnter={(e) => {
                        if (!addingId) e.currentTarget.style.background = 'var(--bg-secondary, #f8fafc)';
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.background = 'transparent';
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                        <div
                          style={{
                            width: 28,
                            height: 28,
                            borderRadius: '4px',
                            background: 'var(--bg-secondary, #f1f5f9)',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            border: '1px solid var(--border)',
                          }}
                        >
                          <FiServer size={14} color="var(--primary)" />
                        </div>
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                            <span style={{ fontWeight: 600, fontSize: '0.825rem', color: 'var(--text-primary)' }}>
                              {agent.hostname || agent.id}
                            </span>
                            <span
                              style={{
                                width: 7,
                                height: 7,
                                borderRadius: '50%',
                                background: isOnline ? 'var(--success, #10b981)' : 'var(--text-tertiary, #94a3b8)',
                              }}
                              title={agent.status}
                            />
                          </div>
                          <div style={{ fontSize: '0.72rem', color: 'var(--text-tertiary)', fontFamily: 'monospace' }}>
                            {agent.id} • {agent.ip || agent.ip_address || 'No IP'}
                          </div>
                        </div>
                      </div>

                      <div>
                        {isAdding ? (
                          <FiLoader size={15} className="animate-spin" color="var(--primary)" />
                        ) : (
                          <span
                            style={{
                              fontSize: '0.725rem',
                              color: 'var(--primary)',
                              fontWeight: 600,
                              padding: '0.2rem 0.5rem',
                              borderRadius: '4px',
                              background: 'var(--primary-light, rgba(59, 130, 246, 0.1))',
                            }}
                          >
                            + Add
                          </span>
                        )}
                      </div>
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
