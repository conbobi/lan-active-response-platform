// src/api/incidents.js
import api from './api';

export const mapIncident = (inc) => {
  if (!inc) return null;
  return {
    id: inc.id,
    title: inc.title || inc.name || `Incident #${inc.id}`,
    description: inc.description || 'No detailed description provided.',
    severity: inc.severity ? inc.severity.toLowerCase() : 'medium',
    status: inc.status ? inc.status.toLowerCase() : 'open',
    assignedTo: inc.assigned_to || inc.assignedTo || 'Unassigned',
    agentId: inc.agent_id || inc.agentId || 'N/A',
    riskScore: inc.risk_score !== undefined ? inc.risk_score : (inc.riskScore || 0),
    notes: inc.notes || '',
    resolvedAt: inc.resolved_at || inc.resolvedAt || null,
    createdAt: inc.created_at || inc.createdAt || new Date().toISOString(),
    updatedAt: inc.updated_at || inc.updatedAt || new Date().toISOString(),
    culpritProcess: inc.culprit_process || null,
    parentProcess: inc.parent_process || null,
    networkIndicators: Array.isArray(inc.network_indicators) ? inc.network_indicators : [],
    factorsBreakdown: Array.isArray(inc.factors_breakdown) ? inc.factors_breakdown : [],
  };
};

export const getIncidents = async () => {
  try {
    const data = await api.get('/incidents/');
    return Array.isArray(data) ? data.map(mapIncident) : [];
  } catch (err) {
    console.error('API /incidents/ error:', err);
    throw err;
  }
};

export const getIncident = async (incidentId) => {
  try {
    const data = await api.get(`/incidents/${incidentId}`);
    return mapIncident(data);
  } catch (err) {
    console.warn(`API getIncident error for ${incidentId}:`, err);
    throw err;
  }
};

export const getIncidentTimeline = async (incidentId) => {
  try {
    const data = await api.get(`/incidents/${incidentId}/timeline`);
    return data && data.timeline ? data.timeline : [];
  } catch (err) {
    console.warn(`API getIncidentTimeline error for ${incidentId}:`, err);
    return [];
  }
};

export const getIncidentNotes = async (incidentId) => {
  try {
    const data = await api.get(`/incidents/${incidentId}/notes`);
    return Array.isArray(data) ? data : [];
  } catch (err) {
    console.warn(`API getIncidentNotes error for ${incidentId}:`, err);
    return [];
  }
};

export const addIncidentNote = async (incidentId, content, user = 'admin') => {
  try {
    return await api.post(`/incidents/${incidentId}/notes`, { content, user });
  } catch (err) {
    console.error(`API Error adding note to incident ${incidentId}:`, err);
    throw err;
  }
};

export const updateIncidentStatus = async (incidentId, status, user = 'admin') => {
  try {
    let endpoint = `/incidents/${incidentId}`;
    if (status === 'contained') endpoint = `/incidents/${incidentId}/contain`;
    else if (status === 'resolved') endpoint = `/incidents/${incidentId}/resolve`;
    else if (status === 'false_positive') endpoint = `/incidents/${incidentId}/false-positive`;
    else if (status === 'closed') endpoint = `/incidents/${incidentId}/close`;

    if (endpoint !== `/incidents/${incidentId}`) {
      const data = await api.post(endpoint);
      return mapIncident(data);
    }

    const data = await api.patch(`/incidents/${incidentId}`, { status });
    return mapIncident(data);
  } catch (err) {
    console.error(`API Error updating incident ${incidentId} status:`, err);
    return { id: incidentId, status, updatedAt: new Date().toISOString() };
  }
};

export const assignIncident = async (incidentId, assignee) => {
  try {
    const data = await api.post(`/incidents/${incidentId}/assign`, { user_id: assignee });
    return mapIncident(data);
  } catch (err) {
    console.error(`API Error assigning incident ${incidentId}:`, err);
    return { id: incidentId, assignedTo: assignee, status: 'investigating', updatedAt: new Date().toISOString() };
  }
};

export const executeIncidentAction = async (incidentId, actionType, params = {}, user = 'admin') => {
  try {
    return await api.post(`/incidents/${incidentId}/action`, {
      action_type: actionType,
      params,
      user,
    });
  } catch (err) {
    console.error(`API Error executing action ${actionType} on incident ${incidentId}:`, err);
    throw err;
  }
};

export default {
  mapIncident,
  getIncidents,
  getIncident,
  getIncidentTimeline,
  getIncidentNotes,
  addIncidentNote,
  updateIncidentStatus,
  assignIncident,
  executeIncidentAction,
};
