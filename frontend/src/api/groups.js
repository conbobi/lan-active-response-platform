// src/api/groups.js
import api from './api';

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
 */
export const executeGroupAction = async (groupId, actionType, actionParams = {}, autoRollbackSeconds = null) => {
  return await api.post(`/groups/${groupId}/actions`, {
    action_type: actionType,
    action_params: actionParams,
    auto_rollback_seconds: autoRollbackSeconds,
  });
};

/**
 * Hoàn nguyên (Undo/Rollback) toàn bộ actions đang hiệu lực của nhóm máy.
 */
export const undoAllGroupActions = async (groupId, reason = 'Batch group undo via UI') => {
  return await api.post(`/groups/${groupId}/undo-all`, { reason });
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
};
