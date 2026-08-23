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
    return Array.isArray(data) ? data : [];
  } catch (error) {
    console.error(`API Error in getRiskHistory (${agentId}):`, error);
    return [];
  }
};
