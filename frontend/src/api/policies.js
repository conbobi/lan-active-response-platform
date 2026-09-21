// src/api/policies.js
import api from './api';

/**
 * Lấy danh sách Response Policies từ backend.
 */
export const listPolicies = async (params = {}) => {
  return await api.get('/policies', { params });
};

/**
 * Lấy chi tiết một Policy theo ID.
 */
export const getPolicy = async (policyId) => {
  return await api.get(`/policies/${policyId}`);
};

/**
 * Tạo mới một Response Policy.
 */
export const createPolicy = async (data) => {
  return await api.post('/policies', data);
};

/**
 * Cập nhật một Response Policy.
 */
export const updatePolicy = async (policyId, data) => {
  return await api.put(`/policies/${policyId}`, data);
};

/**
 * Xóa một Response Policy.
 */
export const deletePolicy = async (policyId) => {
  return await api.delete(`/policies/${policyId}`);
};

/**
 * Đánh giá thử nghiệm chính sách (dry-run hoặc execute).
 */
export const evaluatePolicy = async (data) => {
  return await api.post('/policies/evaluate', data);
};

export default {
  listPolicies,
  getPolicy,
  createPolicy,
  updatePolicy,
  deletePolicy,
  evaluatePolicy,
};
