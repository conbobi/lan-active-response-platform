// src/api/flows.js
import api from './api';

export const mapFlow = (f) => {
  if (!f) return null;
  const packets = f.packets_sent ?? f.packets ?? 0;
  const bytes = f.bytes_sent ?? f.bytes ?? 0;
  const proto = (f.protocol || 'TCP').toUpperCase();

  const syn = f.syn !== undefined 
    ? Number(f.syn) 
    : (proto === 'TCP' || proto === 'SYN' ? Math.max(packets, 1) : 0);
  const udp = f.udp !== undefined 
    ? Number(f.udp) 
    : (proto === 'UDP' ? Math.max(packets, 1) : 0);
  const total = f.total !== undefined 
    ? Number(f.total) 
    : (syn + udp > 0 ? syn + udp : Math.max(packets, 1));

  return {
    id: f.id || `flow-${Math.random().toString(36).substring(2, 9)}`,
    agent_id: f.agent_id || 'manager',
    src_ip: f.src_ip || '192.168.10.1',
    dst_ip: f.dst_ip || '192.168.10.2',
    src_port: f.src_port || 0,
    dst_port: f.dst_port || 0,
    protocol: proto,
    packets_sent: packets,
    bytes_sent: bytes,
    syn,
    udp,
    total,
    is_beacon: Boolean(f.is_beacon),
    timestamp: f.timestamp || f.start_time || f.created_at || new Date().toISOString(),
  };
};

export const getTrafficStats = async (params = {}) => {
  try {
    const queryParams = {};
    if (params.agent_id && params.agent_id !== 'all') {
      queryParams.agent_id = params.agent_id;
    }
    if (params.minutes) {
      queryParams.minutes = params.minutes;
    }
    const data = await api.get('/flows/traffic-stats', { params: queryParams });
    const flowList = Array.isArray(data) ? data : data?.flows || [];
    if (flowList.length > 0) {
      return flowList.map(mapFlow).filter(Boolean);
    }
  } catch (err) {
    console.error('API Error in getTrafficStats:', err);
  }
  return null;
};

export const getFlows = async (params = {}) => {
  try {
    const queryParams = {};
    if (params.agent_id && params.agent_id !== 'all') {
      queryParams.agent_id = params.agent_id;
    }
    if (params.minutes) {
      queryParams.minutes = params.minutes;
    }

    // Try traffic-stats first for aggregated time-series
    const statsData = await getTrafficStats(params);
    if (statsData && statsData.length > 0) {
      return statsData;
    }

    const data = await api.get('/flows/', { params: queryParams });
    const flowList = Array.isArray(data) ? data : data?.flows || [];
    if (flowList.length > 0) {
      return flowList.map(mapFlow).filter(Boolean);
    }
    if (Array.isArray(data)) {
    return [];
  } catch (err) {
    console.error('API Error in getFlows:', err);
    throw err;
  }
};

export default { getFlows, getTrafficStats, mapFlow };
