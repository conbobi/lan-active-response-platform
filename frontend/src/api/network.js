import api from './api';

export const getSuspiciousConnections = async (filters = {}) => {
  const params = new URLSearchParams();
  if (filters.agent && filters.agent !== 'all') params.append('agent', filters.agent);
  if (filters.time) params.append('time', filters.time);
  if (filters.risk && filters.risk !== 'all') params.append('risk', filters.risk);
  if (filters.limit) params.append('limit', filters.limit);
  
  const res = await api.get(`/network/suspicious?${params.toString()}`);
  return Array.isArray(res) ? res : (res?.data || []);
};

export const getTopTalkers = async (filters = {}) => {
  const params = new URLSearchParams();
  if (filters.agent && filters.agent !== 'all') params.append('agent', filters.agent);
  if (filters.time) params.append('time', filters.time);
  
  const res = await api.get(`/network/top-talkers?${params.toString()}`);
  return Array.isArray(res) ? res : (res?.data || []);
};

export const getProtocols = async (filters = {}) => {
  const params = new URLSearchParams();
  if (filters.agent && filters.agent !== 'all') params.append('agent', filters.agent);
  if (filters.time) params.append('time', filters.time);
  
  const res = await api.get(`/network/protocols?${params.toString()}`);
  return Array.isArray(res) ? res : (res?.data || []);
};

export const getFlowDetail = async (flowId) => {
  return api.get(`/network/${flowId}`);
};
