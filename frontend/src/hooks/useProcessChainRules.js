// src/hooks/useProcessChainRules.js
import { useState, useEffect, useCallback } from 'react';
import {
  getProcessChainRules,
  createProcessChainRule,
  updateProcessChainRule,
  deleteProcessChainRule,
} from '../api/processChainRules';

export const useProcessChainRules = () => {
  const [chainRules, setChainRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadRules = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getProcessChainRules();
      setChainRules(Array.isArray(data) ? data : []);
      setError(null);
    } catch (err) {
      console.error('Error fetching process chain rules:', err);
      setError(err.message || 'Failed to load process chain rules');
      setChainRules([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadRules();
  }, [loadRules]);

  const handleToggleActive = async (id) => {
    const target = chainRules.find((r) => r.id === id);
    if (!target) return;
    const newStatus = !target.is_active;

    setChainRules((prev) =>
      prev.map((r) => (r.id === id ? { ...r, is_active: newStatus } : r))
    );

    try {
      await updateProcessChainRule(id, { is_active: newStatus });
    } catch (err) {
      console.error(`Failed to toggle chain rule ${id}:`, err);
      setChainRules((prev) =>
        prev.map((r) => (r.id === id ? { ...r, is_active: target.is_active } : r))
      );
      throw err;
    }
  };

  const handleCreateChainRule = async (payload) => {
    try {
      const created = await createProcessChainRule(payload);
      setChainRules((prev) => [created, ...prev]);
      return created;
    } catch (err) {
      console.error('Failed to create process chain rule:', err);
      throw err;
    }
  };

  const handleUpdateChainRule = async (id, payload) => {
    try {
      const updated = await updateProcessChainRule(id, payload);
      setChainRules((prev) =>
        prev.map((r) => (r.id === id ? { ...r, ...updated } : r))
      );
      return updated;
    } catch (err) {
      console.error(`Failed to update process chain rule ${id}:`, err);
      throw err;
    }
  };

  const handleDeleteChainRule = async (id) => {
    const previous = [...chainRules];
    setChainRules((prev) => prev.filter((r) => r.id !== id));
    try {
      await deleteProcessChainRule(id);
    } catch (err) {
      setChainRules(previous);
      console.error(`Failed to delete process chain rule ${id}:`, err);
      throw err;
    }
  };

  return {
    chainRules,
    loading,
    error,
    refreshChainRules: loadRules,
    handleToggleActive,
    handleCreateChainRule,
    handleUpdateChainRule,
    handleDeleteChainRule,
  };
};

export default useProcessChainRules;
