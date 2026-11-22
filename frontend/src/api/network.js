import api from './api';

export const getSuspiciousConnections = async (filters = {}) => {
  const params = new URLSearchParams();
  if (filters.agent && filters.agent !== 'all') params.append('agent', filters.agent);
  if (filters.time) params.append('time', filters.time);
  if (filters.risk && filters.risk !== 'all') params.append('risk', filters.risk);
  if (filters.limit) params.append('limit', filters.limit);

  const res = await api.get(`/network/suspicious?${params.toString()}`);
  return Array.isArray(res) ? res : (res?.data || []);
};

export const getTopTalkers = async (filters = {}) => {
  const params = new URLSearchParams();
  if (filters.agent && filters.agent !== 'all') params.append('agent', filters.agent);
  if (filters.time) params.append('time', filters.time);

  const res = await api.get(`/network/top-talkers?${params.toString()}`);
  return Array.isArray(res) ? res : (res?.data || []);
};

export const getProtocols = async (filters = {}) => {
  const params = new URLSearchParams();
  if (filters.agent && filters.agent !== 'all') params.append('agent', filters.agent);
  if (filters.time) params.append('time', filters.time);

  const res = await api.get(`/network/protocols?${params.toString()}`);
  return Array.isArray(res) ? res : (res?.data || []);
};

export const getFlowDetail = async (flowId) => {
  return api.get(`/network/${flowId}`);
};

function agentNetworkPath(agentId, section) {
  return `/network/agents/${encodeURIComponent(agentId)}/${section}`;
}

const networkAuth = (token) => ({ headers: { Authorization: `Bearer ${token}` }, timeout: 15000 });

export function getAgentNetwork(agentId, section, token, params = {}, signal) {
  return api.get(agentNetworkPath(agentId, section), { ...networkAuth(token), params, signal });
}

export function refreshAgentNetwork(agentId, token) {
  return api.post(agentNetworkPath(agentId, 'refresh'), null, networkAuth(token));
}

export function applyAgentFirewallAction(agentId, token, body) {
  return api.post(agentNetworkPath(agentId, 'firewall/actions'), body, networkAuth(token));
}
