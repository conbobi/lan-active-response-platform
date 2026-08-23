// src/api/process.js
import api from './api';

export const getProcessTree = async (agentId) => {
  try {
    const data = await api.get(`/process/${agentId}/tree`);
    return data;
  } catch (error) {
    console.error(`API Error in getProcessTree (${agentId}):`, error);
    throw error;
  }
};

export const getSuspiciousProcesses = async (agentId) => {
  try {
    const data = await api.get(`/process/${agentId}/suspicious`);
    return Array.isArray(data) ? data : [];
  } catch (error) {
    console.error(`API Error in getSuspiciousProcesses (${agentId}):`, error);
    return [];
  }
};

export const killProcess = async (agentId, pid) => {
  try {
    return await api.post(`/process/${agentId}/kill`, { pid: Number(pid) });
  } catch (error) {
    console.error(`API Error killing process PID ${pid} on ${agentId}:`, error);
    throw error;
  }
};
