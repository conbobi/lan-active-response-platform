// src/hooks/useRiskAssessment.js
import { useState, useCallback } from 'react';
import { evaluateRisk, getRiskHistory } from '../api/risk';

export const useRiskAssessment = () => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [riskResult, setRiskResult] = useState(null);
  const [history, setHistory] = useState([]);

  const handleEvaluateRisk = async (payload) => {
    setLoading(true);
    setError(null);
    try {
      const result = await evaluateRisk(payload);
      setRiskResult(result);
      return result;
    } catch (err) {
      setError(err.message || 'Failed to evaluate risk');
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const fetchRiskHistory = useCallback(async (agentId, limit = 20) => {
    if (!agentId) return;
    setLoading(true);
    try {
      const data = await getRiskHistory(agentId, limit);
      setHistory(data);
    } catch (err) {
      console.error('Error fetching risk history:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  return {
    loading,
    error,
    riskResult,
    history,
    evaluateRisk: handleEvaluateRisk,
    fetchRiskHistory,
  };
};

export default useRiskAssessment;
