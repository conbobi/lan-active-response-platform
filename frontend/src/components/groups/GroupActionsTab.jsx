// src/components/groups/GroupActionsTab.jsx
import React, { useState, useEffect, useCallback } from 'react';
import { getGroupActions, undoAllGroupActions } from '../../api/groups';
import { undoAction } from '../../api/actions';
import ActionTimeline from '../actions/ActionTimeline';
import { FiRefreshCw, FiAlertCircle } from 'react-icons/fi';
import Button from '../ui/Button';

export default function GroupActionsTab({
  groupId,
  refreshTrigger,
  onRefresh,
}) {
  const [actions, setActions] = useState([]);
  const [loading, setLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchActions = useCallback(async () => {
    if (!groupId) return;
    setLoading(true);
    try {
      const data = await getGroupActions(groupId);
      setActions(Array.isArray(data) ? data : []);
      setError(null);
    } catch (err) {
      console.error(`Failed to fetch actions for group ${groupId}`, err);
      setError(err.message || 'Không thể tải lịch sử hành động của nhóm');
    } finally {
      setLoading(false);
    }
  }, [groupId]);

  useEffect(() => {
    fetchActions();
  }, [fetchActions, refreshTrigger]);

  const handleUndoSingle = async (actionId, reason) => {
    setActionLoading(true);
    try {
      await undoAction(actionId, reason);
      await fetchActions();
      if (onRefresh) onRefresh();
    } catch (err) {
      console.error(`Failed to undo action ${actionId}`, err);
      setError(err.response?.data?.detail || err.message || 'Không thể hoàn nguyên hành động');
      throw err;
    } finally {
      setActionLoading(false);
    }
  };

  const handleUndoAll = async (reason) => {
    setActionLoading(true);
    try {
      await undoAllGroupActions(groupId, reason);
      await fetchActions();
      if (onRefresh) onRefresh();
    } catch (err) {
      console.error(`Failed to rollback all group actions for ${groupId}`, err);
      setError(err.response?.data?.detail || err.message || 'Không thể hoàn nguyên toàn bộ hành động của nhóm');
      throw err;
    } finally {
      setActionLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)' }}>
            Lịch sử phản ứng của nhóm ({actions.length} actions)
          </span>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', margin: '0.15rem 0 0 0' }}>
            Bao gồm tất cả các hành động cô lập, chặn IP, cách ly được thực thi trên các máy trong nhóm.
          </p>
        </div>

        <Button
          variant="outline"
          size="sm"
          onClick={fetchActions}
          disabled={loading || actionLoading}
          iconLeft={<FiRefreshCw size={12} className={loading ? 'animate-spin' : ''} />}
        >
          Làm mới
        </Button>
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

      <ActionTimeline
        actions={actions}
        loading={loading}
        actionLoading={actionLoading}
        onUndo={handleUndoSingle}
        onUndoAll={handleUndoAll}
      />
    </div>
  );
}
