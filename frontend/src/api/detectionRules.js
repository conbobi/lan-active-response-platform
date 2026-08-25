// src/api/detectionRules.js
import api from './api';

export const getDetectionRules = async () => {
  const data = await api.get('/rules/detection');
  return Array.isArray(data) ? data : [];
};

export const createDetectionRule = async (ruleData) => {
  return await api.post('/rules/detection', ruleData);
};

export const getDetectionRule = async (ruleId) => {
  return await api.get(`/rules/detection/${ruleId}`);
};

export const updateDetectionRule = async (ruleId, data) => {
  return await api.put(`/rules/detection/${ruleId}`, data);
};

export const deleteDetectionRule = async (ruleId) => {
  return await api.delete(`/rules/detection/${ruleId}`);
};

