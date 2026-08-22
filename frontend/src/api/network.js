// src/api/network.js
import api from './api';
import { getAgents } from './agents';
import { getTopologyLinks, mapTopologyLink, updateTopology, createTopologyLink } from './topology';
import { requestPath, releasePath as releasePathApi } from './path';

export { mapTopologyLink as mapLink };

export const fetchTopology = async () => {
  try {
    const [links, agents] = await Promise.all([
      getTopologyLinks(),
      getAgents(),
    ]);
    return { agents, links };
  } catch (error) {
    console.error('API Error in fetchTopology:', error);
    return { agents: [], links: [] };
  }
};

export const findPath = async (from, to, requiredBandwidth = 100) => {
  try {
    const payload = {
      source_agent_id: from,
      destination_agent_id: to,
      required_bandwidth: Number(requiredBandwidth),
      priority: 1,
      exclude_link_ids: [],
      max_hops: 10,
    };
    const res = await requestPath(payload);
    return {
      session_id: res.session_id,
      path: res.path || [],
      linkIds: res.link_ids || [],
      link_ids: res.link_ids || [],
      totalCost: res.total_cost || 0,
      total_cost: res.total_cost || 0,
      totalLatency: res.total_latency || 0,
      total_latency: res.total_latency || 0,
      allocatedBandwidth: res.allocated_bandwidth || 0,
      allocated_bandwidth: res.allocated_bandwidth || 0,
      avgBandwidth: res.allocated_bandwidth || 0,
      loadRatio: res.load_ratio || 0,
      found: Boolean(res.found),
    };
  } catch (error) {
    console.error('API Error in findPath:', error);
    return {
      session_id: null,
      path: [],
      linkIds: [],
      link_ids: [],
      totalCost: 0,
      totalLatency: 0,
      total_latency: 0,
      allocatedBandwidth: 0,
      avgBandwidth: 0,
      found: false,
    };
  }
};

export const releasePath = async (sessionId, linkIds, allocatedBandwidth = 100) => {
  try {
    const payload = {
      session_id: sessionId,
      link_ids: Array.isArray(linkIds) ? linkIds : [linkIds],
      allocated_bandwidth: Number(allocatedBandwidth),
      timestamp: new Date().toISOString(),
    };
    return await releasePathApi(payload);
  } catch (error) {
    console.error('API Error in releasePath:', error);
    return null;
  }
};

export const simulateFailure = async (linkId, currentLinks = []) => {
  try {
    let targetLink = currentLinks.find((l) => l.id === linkId);
    if (!targetLink) {
      const linksData = await getTopologyLinks();
      targetLink = linksData.find((l) => l.id === linkId);
    }

    if (!targetLink) {
      throw new Error(`Link ${linkId} not found`);
    }

    const sourceId = targetLink.source_agent_id || (typeof targetLink.source === 'object' ? targetLink.source.id : targetLink.source);
    const targetId = targetLink.target_agent_id || (typeof targetLink.target === 'object' ? targetLink.target.id : targetLink.target);
    const newIsActive = !targetLink.isActive;

    const payload = {
      link_id: linkId,
      source_agent_id: sourceId,
      target_agent_id: targetId,
      new_latency: newIsActive ? (targetLink.latency || 10) : 999,
      new_load: newIsActive ? (targetLink.load || 0) : 200,
      new_packet_loss: newIsActive ? (targetLink.packet_loss || 0) : 100,
      is_active: newIsActive,
      timestamp: new Date().toISOString(),
      reason: 'simulate_failure',
    };

    await updateTopology(payload);

    const updatedTopology = await fetchTopology();
    const updatedLink = updatedTopology.links.find((l) => l.id === linkId) || { ...targetLink, isActive: newIsActive };

    return { links: updatedTopology.links, link: updatedLink };
  } catch (error) {
    console.error('API Error in simulateFailure:', error);
    const refreshed = await fetchTopology();
    return { links: refreshed.links, link: null };
  }
};

export const createLink = async (payload) => {
  try {
    return await createTopologyLink(payload);
  } catch (error) {
    console.error('API Error in createLink:', error);
    return null;
  }
};