// src/hooks/usePolicies.js
import { useState, useCallback, useEffect } from 'react';
import {
  listPolicies,
  createPolicy as apiCreatePolicy,
  updatePolicy as apiUpdatePolicy,
  deletePolicy as apiDeletePolicy,
  evaluatePolicy as apiEvaluatePolicy,
} from '../api/policies';

export const usePolicies = ({ autoFetch = true } = {}) => {
  const [policies, setPolicies] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [evaluating, setEvaluating] = useState(false);
  const [evaluationResult, setEvaluationResult] = useState(null);

  const fetchPolicies = useCallback(async () => {
    setLoading(true);
    try {
      const data = await listPolicies();
      const list = Array.isArray(data) ? data : [];
      // Sắp xếp mặc định: Priority giảm dần (lớn nhất lên trước)
      list.sort((a, b) => (b.priority || 0) - (a.priority || 0));
      setPolicies(list);
      setError(null);
      return list;
    } catch (err) {
      console.error('Failed to fetch response policies', err);
      setError(err.response?.data?.detail || err.message || 'Failed to fetch policies');
      return [];
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (autoFetch) {
      fetchPolicies();
    }
  }, [autoFetch, fetchPolicies]);

  const handleCreatePolicy = async (data) => {
    try {
      const newPolicy = await apiCreatePolicy(data);
      setPolicies((prev) => {
        const updated = [...prev, newPolicy];
        return updated.sort((a, b) => (b.priority || 0) - (a.priority || 0));
      });
      await fetchPolicies();
      return newPolicy;
    } catch (err) {
      console.error('Failed to create policy', err);
      throw err;
    }
  };

  const handleUpdatePolicy = async (id, data) => {
    try {
      const updated = await apiUpdatePolicy(id, data);
      setPolicies((prev) => {
        const list = prev.map((p) => (p.id === id ? { ...p, ...updated } : p));
        return list.sort((a, b) => (b.priority || 0) - (a.priority || 0));
      });
      await fetchPolicies();
      return updated;
    } catch (err) {
      console.error(`Failed to update policy ${id}`, err);
      throw err;
    }
  };

  const handleDeletePolicy = async (id) => {
    try {
      await apiDeletePolicy(id);
      setPolicies((prev) => prev.filter((p) => p.id !== id));
      return true;
    } catch (err) {
      console.error(`Failed to delete policy ${id}`, err);
      throw err;
    }
  };

  const handleToggleActive = async (id, currentActive) => {
    const nextState = !currentActive;
    // Optimistic UI update
    setPolicies((prev) =>
      prev.map((p) => (p.id === id ? { ...p, is_active: nextState } : p))
    );
    try {
      const updated = await apiUpdatePolicy(id, { is_active: nextState });
      setPolicies((prev) =>
        prev.map((p) => (p.id === id ? { ...p, ...updated } : p))
      );
      return updated;
    } catch (err) {
      console.error(`Failed to toggle policy ${id}`, err);
      // Rollback optimistic update
      setPolicies((prev) =>
        prev.map((p) => (p.id === id ? { ...p, is_active: currentActive } : p))
      );
      throw err;
    }
  };

  const handleEvaluate = async (params) => {
    setEvaluating(true);
    setEvaluationResult(null);
    try {
      const res = await apiEvaluatePolicy(params);
      setEvaluationResult(res);
      return res;
    } catch (err) {
      console.error('Failed to evaluate policy', err);
      throw err;
    } finally {
      setEvaluating(false);
    }
  };

  return {
    policies,
    loading,
    error,
    evaluating,
    evaluationResult,
    setEvaluationResult,
    fetchPolicies,
    refreshPolicies: fetchPolicies,
    createPolicy: handleCreatePolicy,
    updatePolicy: handleUpdatePolicy,
    deletePolicy: handleDeletePolicy,
    toggleActive: handleToggleActive,
    evaluatePolicy: handleEvaluate,
  };
};

export default usePolicies;
