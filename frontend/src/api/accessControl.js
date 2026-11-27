// Host IP block / unblock (Agent firewall). Every state shown comes from the Manager, never assumed.
import api from './api.js';

const BASE = '/access-control';

export const listBlocks = (params = {}) => api.get(`${BASE}/blocks`, { params });
export const getBlock = (id) => api.get(`${BASE}/blocks/${id}`);
export const getSuggestions = (incidentId) => api.get(`${BASE}/incidents/${incidentId}/suggestions`);
export const requestBlock = (body) => api.post(`${BASE}/blocks`, body);
export const approveBlock = (id) => api.post(`${BASE}/blocks/${id}/approve`, {});
export const rejectBlock = (id, reason) => api.post(`${BASE}/blocks/${id}/reject`, { reason });
export const requestUnblock = (id, reason) => api.post(`${BASE}/blocks/${id}/unblock`, { reason });
export const decideUnblock = (unblockId, operation) => api.post(`${BASE}/unblocks/${unblockId}/${operation}`, {});
export const checkBlock = (id) => api.post(`${BASE}/blocks/${id}/check`, {});
export const getMe = () => api.get('/auth/me');
