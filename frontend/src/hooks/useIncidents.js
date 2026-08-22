// src/hooks/useIncidents.js
import { useState, useEffect, useCallback } from 'react';
import { getIncidents, assignIncident, resolveIncident, updateIncident } from '../api/incidents';

export const useIncidents = () => {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadIncidents = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getIncidents();
      setIncidents(data);
      setError(null);
    } catch (err) {
      console.error('Failed to load incidents', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadIncidents();
  }, [loadIncidents]);

  const handleAssign = async (id, assignee) => {
    try {
      const updated = await assignIncident(id, assignee);
      setIncidents((prev) => prev.map((inc) => (inc.id === id ? { ...inc, ...updated } : inc)));
      return updated;
    } catch (err) {
      console.error('Error assigning incident', err);
    }
  };

  const handleResolve = async (id) => {
    try {
      const updated = await resolveIncident(id);
      setIncidents((prev) => prev.map((inc) => (inc.id === id ? { ...inc, ...updated } : inc)));
      return updated;
    } catch (err) {
      console.error('Error resolving incident', err);
    }
  };

  return {
    incidents,
    loading,
    error,
    refreshIncidents: loadIncidents,
    handleAssign,
    handleResolve,
  };
};

export default useIncidents;
