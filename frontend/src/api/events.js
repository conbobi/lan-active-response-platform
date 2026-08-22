// src/api/events.js
import api from './api';

export const mapEvent = (e) => ({
  id: e.id,
  agentId: e.agent_id || e.agentId,
  type: e.event_type || e.type || 'security_event',
  severity: e.severity || 'Medium',
  sourceIp: e.source || e.source_ip || e.sourceIp || '10.0.0.1',
  description: e.details?.description || e.description || `Security event ${e.id}`,
  riskScore: e.risk_score || e.riskScore || 50,
  timestamp: e.created_at || e.timestamp || new Date().toISOString(),
});

export const getEvents = async () => {
  try {
    const data = await api.get('/events');
    return Array.isArray(data) ? data.map(mapEvent) : [];
  } catch (err) {
    console.error('API Error in getEvents:', err);
    return [];
  }
};

