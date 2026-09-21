// src/api/actions.js
import api from './api';

export const createAction = async (agentId, actionType, actionParams = {}, incidentId = null, autoRollbackSeconds = null) => {
  return await api.post('/actions', {
    agent_id: agentId,
    action_type: actionType,
    action_params: actionParams,
    incident_id: incidentId,
    auto_rollback_seconds: autoRollbackSeconds,
  });
};

export const getAction = async (actionId) => {
  return await api.get(`/actions/${actionId}`);
};

export const undoAction = async (actionId, reason = 'Manual undo via UI') => {
  return await api.post(`/actions/${actionId}/undo`, { reason });
};

export const undoIncidentActions = async (incidentId, reason = 'Incident batch undo via UI') => {
  return await api.post(`/incidents/${incidentId}/undo-all`, { reason });
};

export const undoAgentActions = async (agentId, reason = 'Agent batch undo via UI') => {
  return await api.post(`/agents/${agentId}/undo-all`, { reason });
};

export const getActionAuditLogs = async (actionId) => {
  return await api.get(`/actions/${actionId}/audit`);
};

export const getAgentActions = async (agentId, limit = 50, offset = 0) => {
  return await api.get(`/agents/${agentId}/actions`, { params: { limit, offset } });
};

export const getIncidentActions = async (incidentId) => {
  return await api.get(`/incidents/${incidentId}/actions`);
};

export const getAutoRollbackSettings = async () => {
  return await api.get('/settings/auto-rollback');
};

export const updateAutoRollbackSettings = async (settings) => {
  return await api.patch('/settings/auto-rollback', settings);
};

export default {
  createAction,
  getAction,
  undoAction,
  undoIncidentActions,
  undoAgentActions,
  getActionAuditLogs,
  getAgentActions,
  getIncidentActions,
  getAutoRollbackSettings,
  updateAutoRollbackSettings,
};
