// src/api/processChainRules.js
import api from './api';

export const getProcessChainRules = async (params = {}) => {
  const data = await api.get('/process-chain-rules/', { params });
  return Array.isArray(data) ? data : [];
};

export const getProcessChainRule = async (id) => {
  return await api.get(`/process-chain-rules/${id}`);
};

export const createProcessChainRule = async (payload) => {
  return await api.post('/process-chain-rules/', payload);
};

export const updateProcessChainRule = async (id, payload) => {
  return await api.put(`/process-chain-rules/${id}`, payload);
};

export const deleteProcessChainRule = async (id) => {
  return await api.delete(`/process-chain-rules/${id}`);
};
