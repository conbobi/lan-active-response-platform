// src/api/processGroups.js
import api from './api';

export const getProcessGroups = async (params = {}) => {
  const data = await api.get('/process-groups/', { params });
  return Array.isArray(data) ? data : [];
};

export const getProcessGroup = async (id) => {
  return await api.get(`/process-groups/${id}`);
};

export const createProcessGroup = async (payload) => {
  return await api.post('/process-groups/', payload);
};

export const updateProcessGroup = async (id, payload) => {
  return await api.put(`/process-groups/${id}`, payload);
};

export const deleteProcessGroup = async (id) => {
  return await api.delete(`/process-groups/${id}`);
};
