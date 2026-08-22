// src/api/incidents.js
import api from './api';

export const mapIncident = (inc) => {
  if (!inc) return null;
  return {
    id: inc.id,
    title: inc.title || inc.name || `Incident #${inc.id}`,
    description: inc.description || 'No description provided.',
    severity: inc.severity ? inc.severity.charAt(0).toUpperCase() + inc.severity.slice(1).toLowerCase() : 'Medium',
    status: inc.status || 'open', // open, in_progress, resolved, closed
    assignedTo: inc.assigned_to || inc.assignedTo || 'Unassigned',
    agentId: inc.agent_id || inc.agentId || 'N/A',
    createdAt: inc.created_at || inc.createdAt || new Date().toISOString(),
    updatedAt: inc.updated_at || inc.updatedAt || new Date().toISOString(),
  };
};

export const getIncidents = async () => {
  try {
    const data = await api.get('/incidents');
    return Array.isArray(data) ? data.map(mapIncident) : [];
  } catch (err) {
    console.warn('API /incidents not found or error, using default incidents data');
    return [
      {
        id: 'INC-1001',
        title: 'High CPU Spike & Suspicious Traffic',
        description: 'Agent client4 experiencing CPU > 90% with anomalous bandwidth utilization.',
        severity: 'High',
        status: 'open',
        assignedTo: 'Unassigned',
        agentId: 'client4',
        createdAt: new Date(Date.now() - 3600000).toISOString(),
        updatedAt: new Date(Date.now() - 3600000).toISOString(),
      },
      {
        id: 'INC-1002',
        title: 'Link Degradation & Packet Loss (100%)',
        description: 'Topology link link-c3-c4 simulated down or link packet loss high.',
        severity: 'Critical',
        status: 'in_progress',
        assignedTo: 'SOC Admin',
        agentId: 'client3',
        createdAt: new Date(Date.now() - 7200000).toISOString(),
        updatedAt: new Date(Date.now() - 1800000).toISOString(),
      },
      {
        id: 'INC-1003',
        title: 'Dead Agent Telemetry Failure',
        description: 'Agent agent-client2 missing heartbeats for over 15 minutes.',
        severity: 'Medium',
        status: 'resolved',
        assignedTo: 'Analyst 1',
        agentId: 'client2',
        createdAt: new Date(Date.now() - 86400000).toISOString(),
        updatedAt: new Date(Date.now() - 43200000).toISOString(),
      },
    ];
  }
};

export const updateIncident = async (id, payload) => {
  try {
    const data = await api.patch(`/incidents/${id}`, payload);
    return mapIncident(data);
  } catch (err) {
    console.error(`API Error updating incident ${id}:`, err);
    return { id, ...payload, updatedAt: new Date().toISOString() };
  }
};

export const assignIncident = async (id, assignee) => {
  try {
    const data = await api.post(`/incidents/${id}/assign`, { assignee });
    return mapIncident(data);
  } catch (err) {
    console.error(`API Error assigning incident ${id}:`, err);
    return { id, assignedTo: assignee, status: 'in_progress', updatedAt: new Date().toISOString() };
  }
};

export const resolveIncident = async (id) => {
  try {
    const data = await api.post(`/incidents/${id}/resolve`);
    return mapIncident(data);
  } catch (err) {
    console.error(`API Error resolving incident ${id}:`, err);
    return { id, status: 'resolved', updatedAt: new Date().toISOString() };
  }
};
