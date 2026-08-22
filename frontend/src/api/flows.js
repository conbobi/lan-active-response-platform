// src/api/flows.js
import api from './api';

export const mapFlow = (f) => ({
  id: f.id,
  agent_id: f.agent_id,
  src_ip: f.src_ip || '10.0.0.1',
  dst_ip: f.dst_ip || '10.0.0.2',
  protocol: f.protocol || 'TCP',
  syn: f.packets || 0,
  udp: f.bytes || 0,
  total: (f.packets || 0) + (f.bytes || 0),
  is_beacon: f.is_beacon || false,
  timestamp: f.start_time || f.created_at || new Date().toISOString(),
});

export const getFlows = async () => {
  try {
    const data = await api.get('/flows');
    return Array.isArray(data) ? data.map(mapFlow) : [];
  } catch (err) {
    console.error('API Error in getFlows:', err);
    return [];
  }
};

