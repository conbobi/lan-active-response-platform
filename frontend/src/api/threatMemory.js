// AI Threat Memory: analysis source of an incident and SOC management of memory entries.
import api from './api.js';

export const getAnalysisSource = (incidentId) => api.get(`/ai/incidents/${incidentId}/analysis-source`);
export const runAnalysis = (incidentId, mode) => api.post(`/ai/incidents/${incidentId}/analysis/run`, { mode });
export const markAnalysisIncorrect = (incidentId, reason) => api.post(`/ai/incidents/${incidentId}/analysis/incorrect`, { reason });
export const listThreatMemory = (params = {}) => api.get('/ai/threat-memory', { params });
export const threatMemoryMetrics = (days = 7) => api.get('/ai/threat-memory/metrics', { params: { days } });
export const changeThreatMemory = (id, operation, reason) => api.post(`/ai/threat-memory/${id}/${operation}`, { reason });
