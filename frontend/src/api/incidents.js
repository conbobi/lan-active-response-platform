// src/api/incidents.js
import api from './api';

export const mapIncident = (inc) => {
  if (!inc) return null;
  const agentId = inc.agent_id || inc.agentId || 'N/A';
  const riskScore = inc.risk_score !== undefined ? inc.risk_score : (inc.riskScore !== undefined ? inc.riskScore : 0);
  const assignedTo = inc.assigned_to || inc.assignedTo || 'Unassigned';
  const resolvedAt = inc.resolved_at || inc.resolvedAt || null;
  const labelReason = inc.label_reason || inc.labelReason || '';
  const labeledBy = inc.labeled_by || inc.labeledBy || '';
  const labeledAt = inc.labeled_at || inc.labeledAt || null;
  const createdAt = inc.created_at || inc.createdAt || new Date().toISOString();
  const updatedAt = inc.updated_at || inc.updatedAt || new Date().toISOString();
  const culpritProcess = inc.culprit_process || inc.culpritProcess || null;
  const parentProcess = inc.parent_process || inc.parentProcess || null;
  const networkIndicators = Array.isArray(inc.network_indicators) ? inc.network_indicators : (Array.isArray(inc.networkIndicators) ? inc.networkIndicators : []);
  const factorsBreakdown = Array.isArray(inc.factors_breakdown) ? inc.factors_breakdown : (Array.isArray(inc.factorsBreakdown) ? inc.factorsBreakdown : []);

  return {
    id: inc.id,
    title: inc.title || inc.name || `Incident #${inc.id}`,
    description: inc.description || 'No detailed description provided.',
    severity: inc.severity ? inc.severity.toLowerCase() : 'medium',
    status: inc.status ? inc.status.toLowerCase() : 'open',
    assignedTo,
    assigned_to: assignedTo,
    agentId,
    agent_id: agentId,
    riskScore,
    risk_score: riskScore,
    notes: inc.notes || '',
    resolvedAt,
    resolved_at: resolvedAt,
    label: inc.label || null,
    labelReason,
    label_reason: labelReason,
    labeledBy,
    labeled_by: labeledBy,
    labeledAt,
    labeled_at: labeledAt,
    createdAt,
    created_at: createdAt,
    updatedAt,
    updated_at: updatedAt,
    culpritProcess,
    culprit_process: culpritProcess,
    parentProcess,
    parent_process: parentProcess,
    networkIndicators,
    network_indicators: networkIndicators,
    factorsBreakdown,
    factors_breakdown: factorsBreakdown,
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

export const closeIncident = async (id, { label, label_reason, labeled_by = 'current_user' }) => {
  const data = await api.patch(`/incidents/${id}`, {
    status: 'closed',
    label,
    label_reason,
    labeled_by,
  });
  return mapIncident(data);
};

export const getAIAnalysis = (id) => api.get(`/incidents/${id}/ai-analysis`);
export const regenerateAIAnalysis = (id) => api.post(`/incidents/${id}/ai-analysis/regenerate`);
export const rateAIAnalysis = (id, rating) => api.post(`/incidents/${id}/ai-analysis/rate`, { rating });
export const suggestAIResponse = (id) => api.post(`/incidents/${id}/ai-analysis/suggest-response`);
export const applyAISuggestion = (id, payload = { analyst: 'current_user' }) => api.post(`/incidents/${id}/ai-analysis/apply-suggestion`, payload);
export const dismissAISuggestion = (id, payload = { analyst: 'current_user', reason: '' }) => api.post(`/incidents/${id}/ai-analysis/dismiss-suggestion`, payload);

export default {
  mapIncident,
  getIncidents,
  getIncident,
  getIncidentTimeline,
  getIncidentNotes,
  addIncidentNote,
  updateIncidentStatus,
  closeIncident,
  assignIncident,
  executeIncidentAction,
  getAIAnalysis,
  regenerateAIAnalysis,
  rateAIAnalysis,
  suggestAIResponse,
  applyAISuggestion,
  dismissAISuggestion,
};
