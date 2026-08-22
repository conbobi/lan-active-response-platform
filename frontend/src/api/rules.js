// src/api/rules.js
import api from './api';

export const getRules = async () => {
  try {
    const data = await api.get('/rules');
    return Array.isArray(data) ? data : [];
  } catch (err) {
    console.error('API Error in getRules:', err);
    return [];
  }
};

export const addRule = async (ruleData) => {
  return await api.post('/rules', ruleData);
};

export const deleteRule = async (ruleId) => {
  return await api.delete(`/rules/${ruleId}`);
};

export const getRule = async (ruleId) => {
  return await api.get(`/rules/${ruleId}`);
};
