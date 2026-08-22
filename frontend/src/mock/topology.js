// src/mock/topology.js
// Mock dataset for 3D Network Topology and Graph Shortest Path calculations

export let agents = [
  { id: 'agent-001', name: 'Gateway Alpha', type: 'gateway', ip: '192.168.1.1', status: 'online' },
  { id: 'agent-002', name: 'Firewall Primary', type: 'firewall', ip: '192.168.1.254', status: 'online' },
  { id: 'agent-003', name: 'Core Analyzer A', type: 'analyzer', ip: '10.0.0.10', status: 'online' },
  { id: 'agent-004', name: 'Sensor Zone 1', type: 'sensor', ip: '10.0.1.15', status: 'online' },
  { id: 'agent-005', name: 'Sensor Zone 2', type: 'sensor', ip: '10.0.1.16', status: 'online' },
  { id: 'agent-006', name: 'Database Server', type: 'server', ip: '10.0.2.100', status: 'online' },
  { id: 'agent-007', name: 'App Server cluster', type: 'server', ip: '10.0.2.200', status: 'online' },
  { id: 'agent-008', name: 'Endpoint Host 08', type: 'endpoint', ip: '192.168.10.8', status: 'online' },
  { id: 'agent-009', name: 'Endpoint Host 09', type: 'endpoint', ip: '192.168.10.9', status: 'offline' },
  { id: 'agent-010', name: 'Backup Gateway', type: 'gateway', ip: '192.168.2.1', status: 'online' },
];

export let links = [
  { id: 'link-001', source: 'agent-001', target: 'agent-002', latency: 4, bandwidth: 1000, isActive: true },
  { id: 'link-002', source: 'agent-001', target: 'agent-003', latency: 8, bandwidth: 1000, isActive: true },
  { id: 'link-003', source: 'agent-002', target: 'agent-003', latency: 6, bandwidth: 1000, isActive: true },
  { id: 'link-004', source: 'agent-002', target: 'agent-004', latency: 12, bandwidth: 500, isActive: true },
  { id: 'link-005', source: 'agent-003', target: 'agent-005', latency: 15, bandwidth: 500, isActive: true },
  { id: 'link-006', source: 'agent-004', target: 'agent-006', latency: 10, bandwidth: 1000, isActive: true },
  { id: 'link-007', source: 'agent-005', target: 'agent-006', latency: 18, bandwidth: 500, isActive: true },
  { id: 'link-008', source: 'agent-006', target: 'agent-007', latency: 3, bandwidth: 2000, isActive: true },
  { id: 'link-009', source: 'agent-007', target: 'agent-008', latency: 25, bandwidth: 100, isActive: true },
  { id: 'link-010', source: 'agent-007', target: 'agent-009', latency: 30, bandwidth: 100, isActive: false },
  { id: 'link-011', source: 'agent-001', target: 'agent-010', latency: 5, bandwidth: 2000, isActive: true },
  { id: 'link-012', source: 'agent-010', target: 'agent-005', latency: 14, bandwidth: 1000, isActive: true },
  { id: 'link-013', source: 'agent-010', target: 'agent-007', latency: 20, bandwidth: 1000, isActive: true },
  { id: 'link-014', source: 'agent-003', target: 'agent-006', latency: 11, bandwidth: 1000, isActive: true },
  { id: 'link-015', source: 'agent-004', target: 'agent-008', latency: 35, bandwidth: 100, isActive: true },
];

/**
 * Dijkstra Algorithm for Shortest Path calculation
 */
export const calculateShortestPath = (sourceId, targetId, activeLinksOnly = true) => {
  const currentLinks = activeLinksOnly ? links.filter((l) => l.isActive) : links;

  // Build adjacency list
  const graph = {};
  agents.forEach((a) => {
    graph[a.id] = [];
  });

  currentLinks.forEach((l) => {
    const u = typeof l.source === 'object' ? l.source.id : l.source;
    const v = typeof l.target === 'object' ? l.target.id : l.target;
    if (graph[u] && graph[v]) {
      graph[u].push({ node: v, weight: l.latency, linkId: l.id, bandwidth: l.bandwidth });
      graph[v].push({ node: u, weight: l.latency, linkId: l.id, bandwidth: l.bandwidth });
    }
  });

  const distances = {};
  const previous = {};
  const prevLinks = {};
  const unvisited = new Set();

  agents.forEach((a) => {
    distances[a.id] = Infinity;
    previous[a.id] = null;
    prevLinks[a.id] = null;
    unvisited.add(a.id);
  });

  distances[sourceId] = 0;

  while (unvisited.size > 0) {
    // Find node with min distance
    let current = null;
    let minDist = Infinity;
    for (const node of unvisited) {
      if (distances[node] < minDist) {
        minDist = distances[node];
        current = node;
      }
    }

    if (current === null || minDist === Infinity) break;
    if (current === targetId) break;

    unvisited.delete(current);

    const neighbors = graph[current] || [];
    for (const edge of neighbors) {
      if (unvisited.has(edge.node)) {
        const alt = distances[current] + edge.weight;
        if (alt < distances[edge.node]) {
          distances[edge.node] = alt;
          previous[edge.node] = current;
          prevLinks[edge.node] = { linkId: edge.linkId, bandwidth: edge.bandwidth, latency: edge.weight };
        }
      }
    }
  }

  if (distances[targetId] === Infinity) {
    return { path: [], linkIds: [], totalLatency: 0, avgBandwidth: 0, found: false };
  }

  // Reconstruct path
  const pathNodes = [];
  const pathLinkIds = [];
  let totalBw = 0;
  let edgeCount = 0;
  let curr = targetId;

  while (curr !== null) {
    pathNodes.unshift(curr);
    if (prevLinks[curr]) {
      pathLinkIds.unshift(prevLinks[curr].linkId);
      totalBw += prevLinks[curr].bandwidth;
      edgeCount++;
    }
    curr = previous[curr];
  }

  return {
    path: pathNodes,
    linkIds: pathLinkIds,
    totalLatency: distances[targetId],
    avgBandwidth: edgeCount > 0 ? Math.round(totalBw / edgeCount) : 0,
    found: true,
  };
};

export const simulateLinkFailureMock = (linkId) => {
  let targetLink = null;
  links = links.map((l) => {
    if (l.id === linkId) {
      targetLink = { ...l, isActive: !l.isActive };
      return targetLink;
    }
    return l;
  });

  return { links: [...links], link: targetLink };
};

export default { agents, links };
