// src/hooks/useActions.js
import { useState, useCallback, useEffect } from 'react';
import {
  createAction,
  undoAction,
  undoIncidentActions,
  undoAgentActions,
  getIncidentActions,
  getAgentActions,
  listAllActions,
} from '../api/actions';

export const useActions = ({
  agentId = null,
  incidentId = null,
  isGlobal = false,
  autoFetch = true,
  pollIntervalMs = 0,
} = {}) => {
  const [actions, setActions] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [actionLoading, setActionLoading] = useState(false);

  const fetchActions = useCallback(async () => {
    if (!agentId && !incidentId && !isGlobal) return;
    setLoading(true);
    try {
      let data = [];
      if (incidentId) {
        data = await getIncidentActions(incidentId);
      } else if (agentId) {
        data = await getAgentActions(agentId);
      } else if (isGlobal) {
        data = await listAllActions();
      }
      setActions(Array.isArray(data) ? data : []);
      setError(null);
      return data;
    } catch (err) {
      console.error('Failed to load response actions', err);
      setError(err.message || 'Failed to fetch response actions');
      return [];
    } finally {
      setLoading(false);
    }
  }, [agentId, incidentId, isGlobal]);

  useEffect(() => {
    if (autoFetch && (agentId || incidentId || isGlobal)) {
      fetchActions();
    }
  }, [autoFetch, agentId, incidentId, isGlobal, fetchActions]);

  // Polling support for live updates & auto-rollback status changes
  useEffect(() => {
    if (pollIntervalMs > 0 && (agentId || incidentId || isGlobal)) {
      const timer = setInterval(() => {
        // Fetch quietly without triggering full loading spinner
        if (incidentId) {
          getIncidentActions(incidentId).then((d) => Array.isArray(d) && setActions(d)).catch(() => {});
        } else if (agentId) {
          getAgentActions(agentId).then((d) => Array.isArray(d) && setActions(d)).catch(() => {});
        } else if (isGlobal) {
          listAllActions().then((d) => Array.isArray(d) && setActions(d)).catch(() => {});
        }
      }, pollIntervalMs);

      return () => clearInterval(timer);
    }
  }, [pollIntervalMs, agentId, incidentId, isGlobal]);

  const handleCreate = async (type, params = {}, autoRollbackSecs = null) => {
    if (!agentId) throw new Error('Agent ID is required to create action');
    try {
      setActionLoading(true);
      const res = await createAction(agentId, type, params, incidentId, autoRollbackSecs);
      await fetchActions();
      return res;
    } catch (err) {
      console.error('Failed to create action', err);
      throw err;
    } finally {
      setActionLoading(false);
    }
  };

  const handleUndo = async (actionId, reason) => {
    try {
      setActionLoading(true);
      const res = await undoAction(actionId, reason);
      // Optimistic update
      setActions((prev) =>
        prev.map((act) => (act.id === actionId ? { ...act, ...res, status: 'reverted' } : act))
      );
      await fetchActions();
      return res;
    } catch (err) {
      console.error(`Failed to undo action ${actionId}`, err);
      throw err;
    } finally {
      setActionLoading(false);
    }
  };

  const handleUndoAll = async (reason) => {
    try {
      setActionLoading(true);
      let res;
      if (incidentId) {
        res = await undoIncidentActions(incidentId, reason);
      } else if (agentId) {
        res = await undoAgentActions(agentId, reason);
      }
      await fetchActions();
      return res;
    } catch (err) {
      console.error('Failed to batch undo actions', err);
      throw err;
    } finally {
      setActionLoading(false);
    }
  };

  // Bulk undo multiple actions by list of action IDs
  const handleBulkUndo = async (actionIds = [], reason = 'Bulk undo via UI', onProgress = null) => {
    if (!actionIds || actionIds.length === 0) return { succeeded: 0, failed: 0, results: [] };
    setActionLoading(true);
    const results = [];
    let succeeded = 0;
    let failed = 0;

    for (let i = 0; i < actionIds.length; i++) {
      const id = actionIds[i];
      try {
        const res = await undoAction(id, reason);
        succeeded++;
        results.push({ actionId: id, status: 'success', data: res });
      } catch (err) {
        failed++;
        results.push({ actionId: id, status: 'failed', error: err.message });
      }
      if (onProgress) {
        onProgress(i + 1, actionIds.length);
      }
    }

    await fetchActions();
    setActionLoading(false);
    return { succeeded, failed, results };
  };

  return {
    actions,
    loading,
    error,
    actionLoading,
    fetchActions,
    fetchAllActions: fetchActions,
    handleCreate,
    handleUndo,
    handleUndoAll,
    handleBulkUndo,
  };
};

export default useActions;
