// src/api/process.js
import api from './api';

export const getProcessTree = async (agentId) => {
  try {
    const data = await api.get(`/process/${agentId}/tree`);
    return data?.data ?? data;
  } catch (error) {
    console.error(`API Error in getProcessTree (${agentId}):`, error);
    throw error;
  }
};

export const getSuspiciousProcesses = async (agentId) => {
  try {
    const data = await api.get(`/process/${agentId}/suspicious`);
    const list = data?.data ?? data;
    return Array.isArray(list) ? list : [];
  } catch (error) {
    console.error(`API Error in getSuspiciousProcesses (${agentId}):`, error);
    return [];
  }
};

export async function getProcessDetail(agentId, pid) {
  const res = await api.get(`/process/${agentId}/process/${pid}`);
  return res?.data ?? res;
}

export async function killProcess(agentId, pid, options = {}) {
  let reason = "Manual analyst action";
  let killTree = false;

  if (typeof options === 'boolean') {
    killTree = options;
  } else if (options && typeof options === 'object') {
    killTree = Boolean(options.killTree ?? options.kill_tree ?? false);
    reason = options.reason || "Manual analyst action";
  }

  const res = await api.post(`/process/${agentId}/process/${pid}/kill`, {
    reason,
    kill_tree: killTree,
    confirmed: options.confirmed === true,
    process_start_time: options.target?.process_start_time,
    parent_pid: options.target?.parent_pid ?? options.target?.ppid,
    exe_path: options.target?.exe_path || options.target?.exe,
  });
  return res?.data ?? res;
}

export default {
  getProcessTree,
  getSuspiciousProcesses,
  getProcessDetail,
  killProcess,
};
