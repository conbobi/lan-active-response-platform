// Incident containment (evidence, file quarantine/restore, verified process stop). States come from the Manager.
import api from './api.js';

export const getContainment = (incidentId) => api.get(`/containment/incidents/${incidentId}/overview`);
export const requestContainment = (incidentId, kind, target, reason) =>
  api.post(`/containment/incidents/${incidentId}/actions`, { kind, target, reason });
export const decideContainment = (actionId, operation, reason) =>
  api.post(`/containment/actions/${actionId}/${operation}`, { reason });
