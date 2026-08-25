// src/hooks/useDetectionRules.js
import { useState, useEffect, useCallback } from 'react';
import {
  getDetectionRules,
  createDetectionRule,
  updateDetectionRule,
  deleteDetectionRule,
} from '../api/detectionRules';

export const useDetectionRules = () => {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadRules = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getDetectionRules();
      setRules(Array.isArray(data) ? data : []);
      setError(null);
    } catch (err) {
      console.error('Error fetching detection rules:', err);
      setError(err.message || 'Failed to load detection rules');
      setRules([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadRules();
  }, [loadRules]);

  const handleToggleRule = async (ruleId) => {
    const target = rules.find((r) => r.rule_id === ruleId);
    if (!target) return;
    const newStatus = !target.enabled;
    setRules((prev) =>
      prev.map((r) => (r.rule_id === ruleId ? { ...r, enabled: newStatus } : r))
    );
    try {
      await updateDetectionRule(ruleId, { enabled: newStatus });
    } catch (err) {
      console.error(`Failed to toggle rule ${ruleId}:`, err);
      setRules((prev) =>
        prev.map((r) => (r.rule_id === ruleId ? { ...r, enabled: target.enabled } : r))
      );
      throw err;
    }
  };

  const handleUpdateWeight = async (ruleId, newWeight) => {
    const numericWeight = parseFloat(newWeight);
    if (isNaN(numericWeight)) return;

    const target = rules.find((r) => r.rule_id === ruleId);
    const oldWeight = target ? target.weight : 1.0;

    setRules((prev) =>
      prev.map((r) => (r.rule_id === ruleId ? { ...r, weight: numericWeight } : r))
    );

    try {
      await updateDetectionRule(ruleId, { weight: numericWeight });
    } catch (err) {
      console.error(`Failed to update weight for ${ruleId}:`, err);
      setRules((prev) =>
        prev.map((r) => (r.rule_id === ruleId ? { ...r, weight: oldWeight } : r))
      );
      throw err;
    }
  };

  const handleUpdateBaseScore = async (ruleId, newBaseScore) => {
    const numericScore = parseFloat(newBaseScore);
    if (isNaN(numericScore)) return;

    const target = rules.find((r) => r.rule_id === ruleId);
    const oldScore = target ? target.base_score : 1.0;

    setRules((prev) =>
      prev.map((r) => (r.rule_id === ruleId ? { ...r, base_score: numericScore } : r))
    );

    try {
      await updateDetectionRule(ruleId, { base_score: numericScore });
    } catch (err) {
      console.error(`Failed to update base score for ${ruleId}:`, err);
      setRules((prev) =>
        prev.map((r) => (r.rule_id === ruleId ? { ...r, base_score: oldScore } : r))
      );
      throw err;
    }
  };

  const handleUpdateRule = async (ruleId, payload) => {
    try {
      const updated = await updateDetectionRule(ruleId, payload);
      setRules((prev) =>
        prev.map((r) => (r.rule_id === ruleId ? { ...r, ...(updated || payload) } : r))
      );
      return updated;
    } catch (err) {
      console.error(`Failed to update rule ${ruleId}:`, err);
      throw err;
    }
  };

  const handleCreateRule = async (ruleData) => {
    try {
      const created = await createDetectionRule(ruleData);
      setRules((prev) => [...prev, created || ruleData]);
      return created || ruleData;
    } catch (err) {
      console.error('Failed to create rule:', err);
      throw err;
    }
  };

  const handleDeleteRule = async (ruleId) => {
    const previousRules = [...rules];
    setRules((prev) => prev.filter((r) => r.rule_id !== ruleId));
    try {
      await deleteDetectionRule(ruleId);
    } catch (err) {
      console.error(`Failed to delete rule ${ruleId}:`, err);
      setRules(previousRules);
      throw err;
    }
  };

  return {
    rules,
    loading,
    error,
    refreshRules: loadRules,
    handleToggleRule,
    handleUpdateWeight,
    handleUpdateBaseScore,
    handleUpdateRule,
    handleCreateRule,
    handleDeleteRule,
  };
};

export default useDetectionRules;

