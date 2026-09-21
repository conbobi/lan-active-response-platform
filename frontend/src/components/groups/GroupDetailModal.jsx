// src/components/groups/GroupDetailModal.jsx
import React, { useState, useEffect, useCallback, useMemo } from 'react';
import Modal from '../ui/Modal';
import Button from '../ui/Button';
import Badge from '../ui/Badge';
import GroupMembersTab from './GroupMembersTab';
import GroupActionsTab from './GroupActionsTab';
import GroupPoliciesTab from './GroupPoliciesTab';
import GroupAuditTab from './GroupAuditTab';
import IsolateGroupConfirmModal from './IsolateGroupConfirmModal';
import RollbackConfirmModal from '../actions/RollbackConfirmModal';
import { getGroup, executeGroupAction, undoAllGroupActions } from '../../api/groups';
import {
  FiUsers,
  FiClock,
  FiShield,
  FiActivity,
  FiLock,
  FiRotateCcw,
  FiAlertCircle,
  FiCheckCircle,
  FiLoader,
  FiInfo,
} from 'react-icons/fi';

const getGroupEmoji = (name = '') => {
  const lower = name.toLowerCase();
  if (lower.includes('hr') || lower.includes('human')) return '🏢';
  if (lower.includes('it') || lower.includes('tech')) return '💻';
  if (lower.includes('finance') || lower.includes('account')) return '💰';
  if (lower.includes('server') || lower.includes('infra')) return '🖥️';
  return '👥';
};

export default function GroupDetailModal({
  isOpen,
  group,
  onClose,
  onRefresh,
}) {
  const [activeTab, setActiveTab] = useState('members');
  const [groupDetail, setGroupDetail] = useState(group || null);
  const [loading, setLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);
  const [refreshTrigger, setRefreshTrigger] = useState(0);

  // Modals
  const [isolateModalOpen, setIsolateModalOpen] = useState(false);
  const [rollbackModalOpen, setRollbackModalOpen] = useState(false);

  // Toast notification state
  const [toast, setToast] = useState(null);

  const showToast = useCallback((message, type = 'info', duration = 6000) => {
    setToast({ message, type, id: Date.now() });
    if (duration > 0) {
      setTimeout(() => {
        setToast((current) => (current?.message === message ? null : current));
      }, duration);
    }
  }, []);

  const fetchDetail = useCallback(async () => {
    if (!group?.id) return;
    try {
      setLoading(true);
      const data = await getGroup(group.id);
      setGroupDetail(data);
    } catch (err) {
      console.error(`Failed to fetch group detail for ${group.id}`, err);
    } finally {
      setLoading(false);
    }
  }, [group?.id]);

  useEffect(() => {
    if (isOpen && group?.id) {
      setActiveTab('members');
      setToast(null);
      fetchDetail();
    }
  }, [isOpen, group?.id, fetchDetail]);

  const currentGroup = groupDetail || group;
  const members = currentGroup?.members || [];
  const memberCount = members.length;
  const hasIsolatedAgents = useMemo(() => {
    return members.some((m) => m.is_isolated === true);
  }, [members]);

  const emoji = getGroupEmoji(currentGroup?.name);

  // Trigger refresh on member change
  const handleMemberChange = async () => {
    await fetchDetail();
    setRefreshTrigger((prev) => prev + 1);
    if (onRefresh) onRefresh();
  };

  // Execute Batch Isolate
  const handleConfirmIsolate = async ({ reason, autoRollbackSeconds }) => {
    setActionLoading(true);
    showToast(`Đang cô lập nhóm ${currentGroup.name}...`, 'info', 0);
    try {
      const res = await executeGroupAction(currentGroup.id, {
        action_type: 'isolate',
        action_params: { reason },
        auto_rollback_seconds: autoRollbackSeconds,
      });

      // Check if partial or full failure
      if (res && res.failed > 0 && res.succeeded === 0) {
        const firstError = res.actions?.find((a) => a.error)?.error || '';
        const matchSecs = firstError.match(/(\d+)s remaining/i);
        if (matchSecs) {
          showToast(`Agent đang trong cooldown. Còn ${matchSecs[1]} giây.`, 'warning', 8000);
        } else {
          showToast(`Cô lập thất bại: ${firstError}`, 'error', 8000);
        }
      } else {
        showToast(`Đã cô lập thành công nhóm ${currentGroup.name}!`, 'success', 5000);
      }

      setIsolateModalOpen(false);
      await fetchDetail();
      setRefreshTrigger((prev) => prev + 1);
      if (onRefresh) onRefresh();
    } catch (err) {
      console.error('Failed to isolate group', err);
      const detail = err.response?.data?.error || err.response?.data?.detail || err.message || '';
      const status = err.response?.status;

      if (status === 429 || detail.toLowerCase().includes('cooldown')) {
        const matchSecs = detail.match(/(\d+)s remaining/i);
        const secs = matchSecs ? matchSecs[1] : 'vài';
        showToast(`Agent đang trong cooldown. Còn ${secs} giây.`, 'warning', 8000);
      } else {
        showToast(`Lỗi cô lập nhóm: ${detail}`, 'error', 7000);
      }
    } finally {
      setActionLoading(false);
    }
  };

  // Execute Batch Rollback / Undo-All
  const handleConfirmRollback = async (reason) => {
    setActionLoading(true);
    showToast(`Đang hoàn nguyên toàn bộ actions của nhóm ${currentGroup.name}...`, 'info', 0);
    try {
      await undoAllGroupActions(currentGroup.id, reason || `Rollback all actions for group ${currentGroup.name}`);
      showToast(`Đã hoàn nguyên toàn bộ actions nhóm ${currentGroup.name}!`, 'success', 5000);
      setRollbackModalOpen(false);
      await fetchDetail();
      setRefreshTrigger((prev) => prev + 1);
      if (onRefresh) onRefresh();
    } catch (err) {
      console.error('Failed to rollback group actions', err);
      const detail = err.response?.data?.detail || err.message || '';
      showToast(`Lỗi hoàn nguyên nhóm: ${detail}`, 'error', 7000);
    } finally {
      setActionLoading(false);
    }
  };

  if (!group) return null;

  return (
    <>
      <Modal
        isOpen={isOpen}
        onClose={actionLoading ? undefined : onClose}
        maxWidth={920}
        title={
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <span style={{ fontSize: '1.4rem', lineHeight: 1 }}>{emoji}</span>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span style={{ fontWeight: 700, fontSize: '1.05rem', color: 'var(--text-primary)' }}>
                  {currentGroup.name}
                </span>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', fontFamily: 'monospace' }}>
                  ({currentGroup.id})
                </span>
                {hasIsolatedAgents ? (
                  <Badge status="danger" label="Has Isolated Agents" showDot={true} />
                ) : (
                  <Badge status="active" label="Normal" showDot={true} />
                )}
              </div>
              {currentGroup.description && (
                <div style={{ fontSize: '0.775rem', color: 'var(--text-secondary)', fontWeight: 400, marginTop: '0.1rem' }}>
                  {currentGroup.description}
                </div>
              )}
            </div>
          </div>
        }
      >
        <div style={{ display: 'flex', flexDirection: 'column', minHeight: '480px' }}>
          {/* Toast Notification Banner inside Modal */}
          {toast && (
            <div
              style={{
                marginBottom: '1rem',
                padding: '0.65rem 0.9rem',
                borderRadius: 'var(--radius-sm, 6px)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: '0.6rem',
                fontSize: '0.825rem',
                background:
                  toast.type === 'error'
                    ? 'rgba(239, 68, 68, 0.12)'
                    : toast.type === 'warning'
                    ? 'rgba(245, 158, 11, 0.12)'
                    : toast.type === 'success'
                    ? 'rgba(16, 185, 129, 0.12)'
                    : 'rgba(59, 130, 246, 0.12)',
                border: `1px solid ${
                  toast.type === 'error'
                    ? 'var(--error, #ef4444)'
                    : toast.type === 'warning'
                    ? 'var(--warning, #f59e0b)'
                    : toast.type === 'success'
                    ? 'var(--success, #10b981)'
                    : 'var(--primary, #3b82f6)'
                }`,
                color:
                  toast.type === 'error'
                    ? 'var(--error, #ef4444)'
                    : toast.type === 'warning'
                    ? 'var(--warning, #f59e0b)'
                    : toast.type === 'success'
                    ? 'var(--success, #10b981)'
                    : 'var(--primary, #3b82f6)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                {toast.type === 'error' && <FiAlertCircle size={16} />}
                {toast.type === 'warning' && <FiAlertCircle size={16} />}
                {toast.type === 'success' && <FiCheckCircle size={16} />}
                {toast.type === 'info' && <FiLoader size={16} className="animate-spin" />}
                <span style={{ fontWeight: 500 }}>{toast.message}</span>
              </div>
              <button
                type="button"
                onClick={() => setToast(null)}
                style={{
                  background: 'none',
                  border: 'none',
                  cursor: 'pointer',
                  color: 'inherit',
                  padding: 0,
                  fontSize: '0.9rem',
                  lineHeight: 1,
                }}
              >
                ✕
              </button>
            </div>
          )}

          {/* 4 Tabs Navigation */}
          <div
            style={{
              display: 'flex',
              borderBottom: '1px solid var(--border)',
              marginBottom: '1.25rem',
              gap: '0.5rem',
            }}
          >
            <button
              type="button"
              onClick={() => setActiveTab('members')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem',
                padding: '0.65rem 1rem',
                border: 'none',
                background: 'transparent',
                cursor: 'pointer',
                fontSize: '0.85rem',
                fontWeight: activeTab === 'members' ? 700 : 500,
                color: activeTab === 'members' ? 'var(--primary)' : 'var(--text-secondary)',
                borderBottom: activeTab === 'members' ? '2px solid var(--primary)' : '2px solid transparent',
                transition: 'all 0.15s',
              }}
            >
              <FiUsers size={15} />
              <span>Members ({memberCount})</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('actions')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem',
                padding: '0.65rem 1rem',
                border: 'none',
                background: 'transparent',
                cursor: 'pointer',
                fontSize: '0.85rem',
                fontWeight: activeTab === 'actions' ? 700 : 500,
                color: activeTab === 'actions' ? 'var(--primary)' : 'var(--text-secondary)',
                borderBottom: activeTab === 'actions' ? '2px solid var(--primary)' : '2px solid transparent',
                transition: 'all 0.15s',
              }}
            >
              <FiClock size={15} />
              <span>Actions History</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('policies')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem',
                padding: '0.65rem 1rem',
                border: 'none',
                background: 'transparent',
                cursor: 'pointer',
                fontSize: '0.85rem',
                fontWeight: activeTab === 'policies' ? 700 : 500,
                color: activeTab === 'policies' ? 'var(--primary)' : 'var(--text-secondary)',
                borderBottom: activeTab === 'policies' ? '2px solid var(--primary)' : '2px solid transparent',
                transition: 'all 0.15s',
              }}
            >
              <FiShield size={15} />
              <span>Applied Policies</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('audit')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem',
                padding: '0.65rem 1rem',
                border: 'none',
                background: 'transparent',
                cursor: 'pointer',
                fontSize: '0.85rem',
                fontWeight: activeTab === 'audit' ? 700 : 500,
                color: activeTab === 'audit' ? 'var(--primary)' : 'var(--text-secondary)',
                borderBottom: activeTab === 'audit' ? '2px solid var(--primary)' : '2px solid transparent',
                transition: 'all 0.15s',
              }}
            >
              <FiActivity size={15} />
              <span>Audit Log</span>
            </button>
          </div>

          {/* Tab Content Body */}
          <div style={{ flex: 1, minHeight: '340px' }}>
            {activeTab === 'members' && (
              <GroupMembersTab
                group={currentGroup}
                onMemberChange={handleMemberChange}
              />
            )}

            {activeTab === 'actions' && (
              <GroupActionsTab
                groupId={currentGroup.id}
                refreshTrigger={refreshTrigger}
                onRefresh={handleMemberChange}
              />
            )}

            {activeTab === 'policies' && (
              <GroupPoliciesTab groupId={currentGroup.id} />
            )}

            {activeTab === 'audit' && (
              <GroupAuditTab
                groupId={currentGroup.id}
                refreshTrigger={refreshTrigger}
              />
            )}
          </div>

          {/* Sticky Footer Toolbar (Luôn hiển thị) */}
          <div
            style={{
              marginTop: '1.5rem',
              paddingTop: '1rem',
              borderTop: '1px solid var(--border)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              background: 'var(--bg-card, #ffffff)',
              flexWrap: 'wrap',
              gap: '0.75rem',
            }}
          >
            {/* Secondary text */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              <FiInfo size={14} color="var(--text-tertiary)" />
              <span>
                <strong>{memberCount} agents</strong> sẽ bị ảnh hưởng bởi các thao tác trên nhóm này.
              </span>
            </div>

            {/* Action Buttons */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
              {/* Rollback All Actions Button (chỉ hiện khi có isolated agent) */}
              {hasIsolatedAgents && (
                <Button
                  variant="success"
                  size="sm"
                  disabled={actionLoading || loading}
                  onClick={() => setRollbackModalOpen(true)}
                  iconLeft={<FiRotateCcw size={13} />}
                >
                  🔄 Rollback All Actions
                </Button>
              )}

              {/* Isolate Entire Group Button */}
              <Button
                variant="danger"
                size="sm"
                disabled={actionLoading || loading || memberCount === 0 || hasIsolatedAgents}
                onClick={() => setIsolateModalOpen(true)}
                iconLeft={<FiLock size={13} />}
                title={
                  memberCount === 0
                    ? 'Nhóm chưa có thành viên nào để cô lập'
                    : hasIsolatedAgents
                    ? 'Nhóm đã có máy đang bị cô lập'
                    : 'Cô lập toàn bộ các máy trong nhóm'
                }
              >
                🛑 Isolate Entire Group
              </Button>
            </div>
          </div>
        </div>
      </Modal>

      {/* Confirmation Modal 1: Isolate Group (2-layer confirmation) */}
      <IsolateGroupConfirmModal
        isOpen={isolateModalOpen}
        group={currentGroup}
        onClose={() => setIsolateModalOpen(false)}
        onConfirm={handleConfirmIsolate}
        loading={actionLoading}
      />

      {/* Confirmation Modal 2: Rollback All Actions */}
      <RollbackConfirmModal
        isOpen={rollbackModalOpen}
        onClose={() => setRollbackModalOpen(false)}
        onConfirm={handleConfirmRollback}
        isBatch={true}
        title={`Xác nhận hoàn nguyên toàn bộ nhóm ${currentGroup.name}`}
      />
    </>
  );
}
