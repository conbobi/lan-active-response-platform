// src/api/topology.js
import api from './api';

export const mapTopologyLink = (link) => {
  if (!link) return null;
  const src = typeof link.source === 'object' ? link.source.id : (link.source_agent_id || link.source);
  const tgt = typeof link.target === 'object' ? link.target.id : (link.target_agent_id || link.target);
  return {
    id: link.id,
    source: src,
    target: tgt,
    source_agent_id: src,
    target_agent_id: tgt,
    capacity: link.capacity ?? link.bandwidth ?? 1000,
    reserved_bandwidth: link.reserved_bandwidth ?? 0,
    latency: link.latency ?? 0,
    load: link.load ?? 0,
    packet_loss: link.packet_loss ?? 0,
    isActive: link.is_active ?? link.isActive ?? true,
    is_active: link.is_active ?? link.isActive ?? true,
    created_at: link.created_at,
    updated_at: link.updated_at,
  };
};

export const getTopologyLinks = async () => {
  try {
    const data = await api.get('/topology/links');
    return Array.isArray(data) ? data.map(mapTopologyLink) : [];
  } catch (error) {
    console.error('API Error in getTopologyLinks:', error);
    return [];
  }
};

export const updateTopology = async (payload) => {
  return await api.post('/topology/update', payload);
};

export const createTopologyLink = async (payload) => {
  return await api.post('/topology/links', payload);
};
