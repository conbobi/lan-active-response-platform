// src/hooks/useActions.js
import { useState, useCallback, useEffect } from 'react';
import {
  createAction,
  undoAction,
  undoIncidentActions,
  undoAgentActions,
  getIncidentActions,
  getAgentActions,
} from '../api/actions';

export const useActions = ({ agentId = null, incidentId = null, autoFetch = true } = {}) => {
  const [actions, setActions] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [actionLoading, setActionLoading] = useState(false);

  const fetchActions = useCallback(async () => {
    if (!agentId && !incidentId) return;
    setLoading(true);
    try {
      let data = [];
      if (incidentId) {
        data = await getIncidentActions(incidentId);
      } else if (agentId) {
        data = await getAgentActions(agentId);
      }
      setActions(Array.isArray(data) ? data : []);
      setError(null);
    } catch (err) {
      console.error('Failed to load response actions', err);
      setError(err.message || 'Failed to fetch response actions');
    } finally {
      setLoading(false);
    }
  }, [agentId, incidentId]);

  useEffect(() => {
    if (autoFetch && (agentId || incidentId)) {
      fetchActions();
    }
  }, [autoFetch, agentId, incidentId, fetchActions]);

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
      // Optimistic/direct update in state
      setActions((prev) =>
        prev.map((act) => (act.id === actionId ? { ...act, ...res } : act))
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

  return {
    actions,
    loading,
    error,
    actionLoading,
    fetchActions,
    handleCreate,
    handleUndo,
    handleUndoAll,
  };
};

export default useActions;
