import api from './api';

// Hàm map trạng thái từ backend (ACTIVE, DEAD, ISOLATED, QUARANTINE) về frontend ('online', 'offline', 'isolated')
const mapStatus = (status, isIsolated = false) => {
  if (isIsolated) return 'isolated';
  const s = String(status || '').toLowerCase();
  if (s === 'active' || s === 'online') return 'online';
  if (s === 'isolated' || s === 'quarantine') return 'isolated';
  if (s === 'dead' || s === 'offline' || s === 'inactive') return 'offline';
  return 'offline';
};

export const getAgents = async () => {
  const response = await api.get('/agents');
  // Backend trả về list các agent, map sang định dạng frontend cần
  return response.map((agent) => ({
    id: agent.id,
    hostname: agent.hostname || agent.id,
    ip: agent.ip_address || agent.ip,
    status: mapStatus(agent.status, agent.is_isolated),
    cpu: agent.cpu || 0,
    ram: agent.ram || 0,
    disk: agent.disk || 0,
    firewall: !agent.is_isolated, // hoặc dùng trường khác nếu có
    isProbe: agent.is_probe,
    is_isolated: agent.is_isolated,
    last_seen: agent.last_seen,
  }));
};
export const isolateAgent = async (agentId) => {
  return await api.post(`/agents/${agentId}/isolate`);
};

export const getAgentHistory = async (agentId) => {
  try {
    const data = await api.get(`/agents/${agentId}/history`);
    return data; // backend trả về mảng {id, agent_id, cpu, ram, disk, timestamp}
  } catch (err) {
    console.error('Failed to fetch agent history', err);
    return [];
  }
};
export const unisolateAgent = async (agentId) => {
  return await api.post(`/agents/${agentId}/unisolate`);
};