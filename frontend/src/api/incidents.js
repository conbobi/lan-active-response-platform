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
  };
};

export const getIncidents = async () => {
  try {
    const data = await api.get('/incidents');
    return Array.isArray(data) ? data.map(mapIncident) : [];
  } catch (err) {
    console.warn('API /incidents error, using fallback incidents dataset:', err);
    return [
      {
        id: 'INC-1001',
        title: 'High CPU Spike & Reverse Shell Activity',
        description: 'Agent client4 detected CPU > 90% with active netcat / nc listener on port 4444.',
        severity: 'high',
        status: 'open',
        assignedTo: 'Unassigned',
        agentId: 'client4',
        riskScore: 88,
        notes: '[system]: Incident generated automatically.',
        createdAt: new Date(Date.now() - 3600000).toISOString(),
        updatedAt: new Date(Date.now() - 3600000).toISOString(),
      },
      {
        id: 'INC-1002',
        title: 'Ransomware Mass File Modification',
        description: 'Agent client1 generated over 50 .encrypted files in /tmp/victim_files.',
        severity: 'critical',
        status: 'contained',
        assignedTo: 'SOC Lead',
        agentId: 'client1',
        riskScore: 95,
        notes: '[SOC Lead]: Automated process tree killed & host network isolated.',
        createdAt: new Date(Date.now() - 7200000).toISOString(),
        updatedAt: new Date(Date.now() - 1800000).toISOString(),
      },
      {
        id: 'INC-1003',
        title: 'LSASS Credential Dump Reading',
        description: 'Attempted access to /tmp/lsass.dump detected by risk assessment rule.',
        severity: 'high',
        status: 'investigating',
        assignedTo: 'Analyst 1',
        agentId: 'client2',
        riskScore: 78,
        notes: '[Analyst 1]: Investigating memory dump artifact.',
        createdAt: new Date(Date.now() - 14400000).toISOString(),
        updatedAt: new Date(Date.now() - 7200000).toISOString(),
      },
      {
        id: 'INC-1004',
        title: 'Scheduled Task Persistence Anomaly',
        description: 'Unusual cron job created under /etc/cron.d by non-privileged process.',
        severity: 'medium',
        status: 'resolved',
        assignedTo: 'Analyst 2',
        agentId: 'client3',
        riskScore: 45,
        notes: '[Analyst 2]: Verified benign monitoring cron job.',
        createdAt: new Date(Date.now() - 86400000).toISOString(),
        updatedAt: new Date(Date.now() - 43200000).toISOString(),
      },
    ];
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
  getIncidentNotes,
  addIncidentNote,
  updateIncidentStatus,
  assignIncident,
  executeIncidentAction,
};
