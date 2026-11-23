// src/hooks/useIncidents.js
import { useState, useEffect, useCallback, useRef } from 'react';
import {
  getIncidents,
  assignIncident,
  updateIncidentStatus,
  addIncidentNote,
  executeIncidentAction,
} from '../api/incidents';
import { useDashboardSocket } from './useDashboardSocket';

export const useIncidents = (finding) => {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [actionLoading, setActionLoading] = useState(false);
  const requestId = useRef(0);
  const refreshTimer = useRef(null);

  const loadIncidents = useCallback(async (showLoading = true) => {
    const request = ++requestId.current;
    if (showLoading) setLoading(true);
    try {
      const data = await getIncidents({ limit: 200, finding: finding || undefined });
      if (request !== requestId.current) return;
      setIncidents(data);
      setError(null);
    } catch (err) {
      if (request !== requestId.current) return;
      console.error('Failed to load incidents', err);
      setError(err.message || 'Failed to fetch security incidents');
    } finally {
      if (request === requestId.current) setLoading(false);
    }
  }, [finding]);

  useEffect(() => {
    loadIncidents(true);
    return () => {
      requestId.current++;
      clearTimeout(refreshTimer.current);
      refreshTimer.current = null;
    };
  }, [loadIncidents]);

  // Realtime updates via WebSocket dashboard connection
  useDashboardSocket(
    useCallback((msg) => {
      if (msg && ['INCIDENT_NEW', 'INCIDENT_CREATED', 'ACTIVITY_UPDATED', 'INCIDENT_UPDATED', 'INCIDENT_STATUS_CHANGED', 'INCIDENT_RESOLVED'].includes(msg.type)) {
        if (refreshTimer.current) return;
        refreshTimer.current = setTimeout(() => {
          refreshTimer.current = null;
          loadIncidents(false);
        }, 2500);
      }
    }, [loadIncidents]),
    () => loadIncidents(false),
  );

  const handleAssign = async (id, assignee) => {
    try {
      setActionLoading(true);
      const updated = await assignIncident(id, assignee);
      setIncidents((prev) => prev.map((inc) => (inc.id === id ? { ...inc, ...updated } : inc)));
      await loadIncidents(false);
      return updated;
    } catch (err) {
      console.error('Error assigning incident', err);
      throw err;
    } finally {
      setActionLoading(false);
    }
  };

  const handleUpdateStatus = async (id, status, user = 'admin') => {
    try {
      setActionLoading(true);
      const updated = await updateIncidentStatus(id, status, user);
      setIncidents((prev) => prev.map((inc) => (inc.id === id ? { ...inc, ...updated } : inc)));
      await loadIncidents(false);
      return updated;
    } catch (err) {
      console.error(`Error updating incident ${id} status to ${status}`, err);
      throw err;
    } finally {
      setActionLoading(false);
    }
  };

  const handleAddNote = async (id, content, user = 'admin') => {
    try {
      const note = await addIncidentNote(id, content, user);
      await loadIncidents(false);
      return note;
    } catch (err) {
      console.error(`Error adding note to incident ${id}`, err);
      throw err;
    }
  };

  const handleExecuteAction = async (id, actionType, params = {}, user = 'admin') => {
    try {
      setActionLoading(true);
      const res = await executeIncidentAction(id, actionType, params, user);
      await loadIncidents(false);
      return res;
    } catch (err) {
      console.error(`Error executing action ${actionType} on incident ${id}`, err);
      throw err;
    } finally {
      setActionLoading(false);
    }
  };

  return {
    incidents,
    loading,
    actionLoading,
    error,
    refreshIncidents: () => loadIncidents(true),
    handleAssign,
    handleUpdateStatus,
    handleAddNote,
    handleExecuteAction,
  };
};

export default useIncidents;
