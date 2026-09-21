// src/api/groups.js
import api from './api';
import { getAgentActions } from './actions';

/**
 * Lấy danh sách tất cả các Agent Group kèm số lượng máy thành viên.
 */
export const listGroups = async () => {
  return await api.get('/groups');
};

/**
 * Lấy thông tin chi tiết một Agent Group kèm danh sách các máy thành viên.
 */
export const getGroup = async (groupId) => {
  return await api.get(`/groups/${groupId}`);
};

/**
 * Tạo mới một Agent Group (tùy chọn custom id, name, description).
 */
export const createGroup = async (data) => {
  return await api.post('/groups', data);
};

/**
 * Cập nhật tên hoặc mô tả của nhóm.
 */
export const updateGroup = async (groupId, data) => {
  return await api.put(`/groups/${groupId}`, data);
};

/**
 * Xóa một Agent Group.
 */
export const deleteGroup = async (groupId) => {
  return await api.delete(`/groups/${groupId}`);
};

/**
 * Thêm một hoặc nhiều agent vào nhóm.
 */
export const addAgentToGroup = async (groupId, agentIds) => {
  const ids = Array.isArray(agentIds) ? agentIds : [agentIds];
  return await api.post(`/groups/${groupId}/agents`, { agent_ids: ids });
};

/**
 * Xóa một agent khỏi nhóm.
 */
export const removeAgentFromGroup = async (groupId, agentId) => {
  return await api.delete(`/groups/${groupId}/agents/${agentId}`);
};

/**
 * Lấy danh sách tất cả các nhóm mà một agent trực thuộc.
 */
export const getAgentGroups = async (agentId) => {
  return await api.get(`/agents/${agentId}/groups`);
};

/**
 * Thực thi batch response action trên toàn bộ nhóm máy.
 * Hỗ trợ cả 2 dạng:
 * 1) executeGroupAction(groupId, { action_type, action_params, auto_rollback_seconds })
 * 2) executeGroupAction(groupId, actionType, actionParams, autoRollbackSeconds)
 */
export const executeGroupAction = async (groupId, actionTypeOrData, actionParams = {}, autoRollbackSeconds = null) => {
  let payload;
  if (typeof actionTypeOrData === 'object' && actionTypeOrData !== null) {
    payload = {
      action_type: actionTypeOrData.action_type || actionTypeOrData.actionType,
      action_params: actionTypeOrData.action_params || actionTypeOrData.actionParams || {},
      auto_rollback_seconds: actionTypeOrData.auto_rollback_seconds ?? actionTypeOrData.autoRollbackSeconds ?? null,
    };
  } else {
    payload = {
      action_type: actionTypeOrData,
      action_params: actionParams,
      auto_rollback_seconds: autoRollbackSeconds,
    };
  }
  return await api.post(`/groups/${groupId}/actions`, payload);
};

/**
 * Hoàn nguyên (Undo/Rollback) toàn bộ actions đang hiệu lực của nhóm máy.
 */
export const undoAllGroupActions = async (groupId, reason = 'Batch group undo via UI') => {
  return await api.post(`/groups/${groupId}/undo-all`, { reason });
};

/**
 * Lấy toàn bộ actions liên quan tới nhóm máy:
 * Truy vấn chi tiết nhóm để lấy danh sách members, sau đó lấy actions của từng member
 * và gom lại, sắp xếp theo thời gian mới nhất.
 */
export const getGroupActions = async (groupId) => {
  try {
    const groupDetail = await getGroup(groupId);
    const members = groupDetail?.members || [];
    if (members.length === 0) return [];

    const actionPromises = members.map(async (member) => {
      try {
        const actions = await getAgentActions(member.agent_id);
        return Array.isArray(actions) ? actions : [];
      } catch (err) {
        console.warn(`Failed to fetch actions for agent ${member.agent_id}`, err);
        return [];
      }
    });

    const results = await Promise.all(actionPromises);
    const allActions = results.flat();

    // Loại bỏ duplicate action id (nếu có)
    const map = new Map();
    allActions.forEach((act) => {
      if (act && act.id && !map.has(act.id)) {
        map.set(act.id, act);
      }
    });

    // Sắp xếp giảm dần theo applied_at || created_at
    const sorted = Array.from(map.values()).sort((a, b) => {
      const timeA = new Date(a.applied_at || a.created_at || 0).getTime();
      const timeB = new Date(b.applied_at || b.created_at || 0).getTime();
      return timeB - timeA;
    });

    return sorted;
  } catch (err) {
    console.error(`Failed to fetch actions for group ${groupId}`, err);
    return [];
  }
};

export default {
  listGroups,
  getGroup,
  createGroup,
  updateGroup,
  deleteGroup,
  addAgentToGroup,
  removeAgentFromGroup,
  getAgentGroups,
  executeGroupAction,
  undoAllGroupActions,
  getGroupActions,
};
