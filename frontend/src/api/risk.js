// src/api/risk.js
import api from './api';

export const evaluateRisk = async (payload) => {
  try {
    return await api.post('/risk/evaluate', payload);
  } catch (error) {
    console.error('API Error in evaluateRisk:', error);
    throw error;
  }
};

export const getRiskHistory = async (agentId, limit = 20) => {
  try {
    const data = await api.get(`/risk/${agentId}/history`, { params: { limit } });
    const records = Array.isArray(data) ? data : [];
    return records.map((r) => ({
      ...r,
      smoothed_score: r.smoothed_score ?? r.score,
    }));
  } catch (error) {
    console.error(`API Error in getRiskHistory (${agentId}):`, error);
    return [];
  }
};

export const getAgentRiskScores = async (agentId, limit = 100) => {
  try {
    const data = await api.get(`/risk/agent/${agentId}`, { params: { limit } });
    const records = Array.isArray(data) ? data : [];
    return records.map((r) => ({
      ...r,
      smoothed_score: r.smoothed_score ?? r.score,
    }));
  } catch (error) {
    console.error(`API Error in getAgentRiskScores (${agentId}):`, error);
    return [];
  }
};

export const getAgentRiskSummary = async (agentId) => {
  try {
    return await api.get(`/risk/agent/${agentId}/summary`);
  } catch (error) {
    console.error(`API Error in getAgentRiskSummary (${agentId}):`, error);
    return { agent_id: agentId, score: 0.0, smoothed_score: 0.0, factors: {} };
  }
};

export const verifyPhase2 = async () => {
  try {
    return await api.get('/risk/verify-phase2');
  } catch (error) {
    console.error('API Error in verifyPhase2:', error);
    throw error;
  }
};
