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

export const getActionAudit = getActionAuditLogs;

export const getAgentActions = async (agentId, limit = 50, offset = 0) => {
  return await api.get(`/agents/${agentId}/actions`, { params: { limit, offset } });
};

export const getActionsByAgent = getAgentActions;

export const getIncidentActions = async (incidentId) => {
  return await api.get(`/incidents/${incidentId}/actions`);
};

export const getAutoRollbackSettings = async () => {
  return await api.get('/settings/auto-rollback');
};

export const updateAutoRollbackSettings = async (settings) => {
  return await api.patch('/settings/auto-rollback', settings);
};

/**
 * Lấy toàn bộ lịch sử actions trong hệ thống.
 * Backend không cung cấp endpoint GET /api/v1/actions nên tổng hợp từ danh sách tất cả agents.
 */
export const listAllActions = async () => {
  try {
    const agents = await api.get('/agents');
    const agentList = Array.isArray(agents) ? agents : [];

    const promises = agentList.map(async (ag) => {
      try {
        const acts = await api.get(`/agents/${ag.id}/actions`, { params: { limit: 100 } });
        return Array.isArray(acts) ? acts : [];
      } catch (err) {
        console.warn(`Failed to fetch actions for agent ${ag.id}`, err);
        return [];
      }
    });

    const results = await Promise.all(promises);
    const flattened = results.flat();

    // Deduplicate by action.id
    const seen = new Set();
    const unique = [];
    for (const act of flattened) {
      if (act && act.id && !seen.has(act.id)) {
        seen.add(act.id);
        unique.push(act);
      }
    }

    // Sắp xếp giảm dần theo thời gian (mới nhất trước)
    return unique.sort((a, b) => {
      const timeA = new Date(a.applied_at || a.created_at || 0).getTime();
      const timeB = new Date(b.applied_at || b.created_at || 0).getTime();
      return timeB - timeA;
    });
  } catch (err) {
    console.error('Failed to list all actions', err);
    return [];
  }
};

export default {
  createAction,
  getAction,
  undoAction,
  undoIncidentActions,
  undoAgentActions,
  getActionAuditLogs,
  getActionAudit,
  getAgentActions,
  getActionsByAgent,
  getIncidentActions,
  getAutoRollbackSettings,
  updateAutoRollbackSettings,
  listAllActions,
};
