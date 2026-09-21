// src/components/groups/GroupMembersTab.jsx
import React, { useState } from 'react';
import AddAgentDropdown from './AddAgentDropdown';
import Button from '../ui/Button';
import Badge from '../ui/Badge';
import { removeAgentFromGroup } from '../../api/groups';
import {
  FiUsers,
  FiTrash2,
  FiServer,
  FiShield,
  FiAlertCircle,
  FiCheckCircle,
  FiLoader,
} from 'react-icons/fi';

export default function GroupMembersTab({ group, onMemberChange }) {
  const [removingId, setRemovingId] = useState(null);
  const [error, setError] = useState('');

  const members = group?.members || [];

  const handleRemove = async (agentId, hostname) => {
    const displayName = hostname || agentId;
    if (!confirm(`Bạn có chắc muốn xóa agent "${displayName}" (${agentId}) khỏi nhóm "${group?.name}"?`)) {
      return;
    }
    setError('');
    setRemovingId(agentId);
    try {
      await removeAgentFromGroup(group.id, agentId);
      if (onMemberChange) {
        await onMemberChange();
      }
    } catch (err) {
      console.error(`Failed to remove agent ${agentId}`, err);
      setError(err.response?.data?.detail || err.message || 'Không thể xóa agent khỏi nhóm');
    } finally {
      setRemovingId(null);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      {/* Top action bar: Summary and Add Button */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '0.75rem',
        }}
      >
        <div>
          <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)' }}>
            Danh sách thành viên ({members.length} agents)
          </span>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', margin: '0.15rem 0 0 0' }}>
            Các agent trực thuộc nhóm này sẽ áp dụng phản ứng theo nhóm và chính sách bảo mật chung.
          </p>
        </div>

        <AddAgentDropdown
          groupId={group?.id}
          currentMembers={members}
          onAdded={onMemberChange}
        />
      </div>

      {error && (
        <div
          style={{
            padding: '0.65rem 0.85rem',
            background: 'rgba(239, 68, 68, 0.1)',
            border: '1px solid var(--error, #ef4444)',
            borderRadius: 'var(--radius-sm, 4px)',
            color: 'var(--error, #ef4444)',
            fontSize: '0.8rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
          }}
        >
          <FiAlertCircle size={15} />
          <span>{error}</span>
        </div>
      )}

      {/* Members Table or Empty State */}
      {members.length === 0 ? (
        <div
          style={{
            padding: '3rem 1.5rem',
            textAlign: 'center',
            background: 'var(--bg-secondary, #f8fafc)',
            borderRadius: 'var(--radius-sm, 6px)',
            border: '1px dashed var(--border)',
          }}
        >
          <FiUsers size={36} style={{ color: 'var(--text-tertiary)', opacity: 0.5, marginBottom: '0.5rem' }} />
          <h4 style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)', margin: '0 0 0.25rem 0' }}>
            Nhóm chưa có thành viên nào
          </h4>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-tertiary)', margin: 0 }}>
            Thêm agent đầu tiên vào nhóm bằng nút "Add Agent to Group" phía trên.
          </p>
        </div>
      ) : (
        <div
          style={{
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius-sm, 6px)',
            overflow: 'hidden',
          }}
        >
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.825rem' }}>
            <thead>
              <tr
                style={{
                  background: 'var(--bg-secondary, #f8fafc)',
                  borderBottom: '1px solid var(--border)',
                  color: 'var(--text-secondary)',
                  fontWeight: 600,
                  fontSize: '0.75rem',
                  textTransform: 'uppercase',
                  letterSpacing: '0.04em',
                }}
              >
                <th style={{ padding: '0.65rem 0.85rem' }}>Agent ID</th>
                <th style={{ padding: '0.65rem 0.85rem' }}>Hostname</th>
                <th style={{ padding: '0.65rem 0.85rem' }}>IP Address</th>
                <th style={{ padding: '0.65rem 0.85rem' }}>Status</th>
                <th style={{ padding: '0.65rem 0.85rem' }}>Isolated?</th>
                <th style={{ padding: '0.65rem 0.85rem', textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {members.map((m, idx) => {
                const isOnline = m.status === 'active' || m.status === 'online';
                const isIsolated = m.is_isolated === true;
                const isRemoving = removingId === m.agent_id;

                return (
                  <tr
                    key={m.agent_id}
                    style={{
                      borderBottom: idx < members.length - 1 ? '1px solid var(--border)' : 'none',
                      background: isIsolated ? 'rgba(239, 68, 68, 0.03)' : 'transparent',
                      transition: 'background 0.15s',
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.background = isIsolated
                        ? 'rgba(239, 68, 68, 0.07)'
                        : 'var(--bg-secondary, #f8fafc)';
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.background = isIsolated ? 'rgba(239, 68, 68, 0.03)' : 'transparent';
                    }}
                  >
                    <td style={{ padding: '0.65rem 0.85rem', fontWeight: 600, fontFamily: 'monospace' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                        <FiServer size={14} color="var(--primary)" />
                        <span>{m.agent_id}</span>
                      </div>
                    </td>
                    <td style={{ padding: '0.65rem 0.85rem', color: 'var(--text-primary)' }}>
                      {m.hostname || 'N/A'}
                    </td>
                    <td style={{ padding: '0.65rem 0.85rem', color: 'var(--text-secondary)', fontFamily: 'monospace' }}>
                      {m.ip_address || 'N/A'}
                    </td>
                    <td style={{ padding: '0.65rem 0.85rem' }}>
                      <Badge
                        status={isOnline ? 'active' : 'inactive'}
                        label={isOnline ? 'Online' : 'Offline'}
                        showDot={true}
                      />
                    </td>
                    <td style={{ padding: '0.65rem 0.85rem' }}>
                      {isIsolated ? (
                        <Badge
                          status="danger"
                          label="Isolated"
                          showDot={true}
                        />
                      ) : (
                        <Badge
                          status="neutral"
                          label="No"
                          showDot={false}
                        />
                      )}
                    </td>
                    <td style={{ padding: '0.65rem 0.85rem', textAlign: 'right' }}>
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={isRemoving}
                        onClick={() => handleRemove(m.agent_id, m.hostname)}
                        title="Remove agent from this group"
                        style={{
                          color: 'var(--error, #ef4444)',
                          padding: '0.25rem 0.5rem',
                        }}
                      >
                        {isRemoving ? (
                          <FiLoader size={14} className="animate-spin" />
                        ) : (
                          <FiTrash2 size={14} />
                        )}
                      </Button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
