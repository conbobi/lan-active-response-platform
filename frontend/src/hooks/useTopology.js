// src/hooks/useTopology.js
import { useState, useEffect, useCallback } from 'react';
import { fetchTopology, findPath, releasePath, simulateFailure } from '../api/network';

export const useTopology = () => {
  const [topology, setTopology] = useState({ agents: [], links: [] });
  const [loading, setLoading] = useState(true);
  const [selectedFrom, setSelectedFrom] = useState('');
  const [selectedTo, setSelectedTo] = useState('');
  const [requiredBandwidth, setRequiredBandwidth] = useState(100);
  const [pathData, setPathData] = useState(null);
  const [toasts, setToasts] = useState([]);

  const addToast = (message, type = 'info') => {
    const id = Date.now() + Math.random();
    setToasts((prev) => [...prev, { id, message, type }]);
    setTimeout(() => {
      removeToast(id);
    }, 4500);
  };

  const removeToast = (id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  };

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const data = await fetchTopology();
      setTopology(data);
      if (data.agents && data.agents.length >= 2 && !selectedFrom) {
        setSelectedFrom(data.agents[0].id);
        setSelectedTo(data.agents[1]?.id || data.agents[0].id);
      }
    } catch (err) {
      console.error('Failed to load topology', err);
      addToast('Failed to load network topology', 'error');
    } finally {
      setLoading(false);
    }
  }, [selectedFrom]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleFindPath = async (from = selectedFrom, to = selectedTo, bw = requiredBandwidth) => {
    if (!from || !to) {
      addToast('Please select both Source and Target agents.', 'warning');
      return;
    }

    if (from === to) {
      addToast('Source and Target agents must be different.', 'warning');
      return;
    }

    try {
      const result = await findPath(from, to, bw);
      setPathData(result);

      if (result.found) {
        addToast(
          `Route found! Latency: ${result.totalLatency || result.total_latency || 0}ms | Bandwidth: ${result.allocatedBandwidth || result.avgBandwidth || bw} Mbps`,
          'success'
        );
      } else {
        addToast(`No route available between ${from} and ${to}`, 'error');
      }
    } catch (err) {
      addToast(err.message || 'Error finding path', 'error');
    }
  };

  const handleReleasePath = async () => {
    if (!pathData || !pathData.found) return;

    try {
      const sessionId = pathData.session_id;
      const linkIds = pathData.link_ids || pathData.linkIds || [];
      const allocatedBw = pathData.allocated_bandwidth || pathData.allocatedBandwidth || requiredBandwidth;

      await releasePath(sessionId, linkIds, allocatedBw);
      addToast('Bandwidth allocated path released successfully', 'success');
      setPathData(null);
      await loadData();
    } catch (err) {
      addToast(err.message || 'Error releasing path', 'error');
    }
  };

  const handleSimulateFailure = async (targetLinkId = null) => {
    let linkIdToBreak = targetLinkId;
    if (!linkIdToBreak) {
      const activeLinks = topology.links.filter((l) => l.isActive);
      if (activeLinks.length === 0) {
        addToast('All links are already broken!', 'warning');
        return;
      }
      const randomLink = activeLinks[Math.floor(Math.random() * activeLinks.length)];
      linkIdToBreak = randomLink.id;
    }

    try {
      const result = await simulateFailure(linkIdToBreak, topology.links);
      const updatedLinks = result.links || topology.links;
      setTopology((prev) => ({ ...prev, links: updatedLinks }));

      const changedLink = result.link || topology.links.find((l) => l.id === linkIdToBreak);
      if (changedLink) {
        const srcId = changedLink.source_agent_id || (typeof changedLink.source === 'object' ? changedLink.source.id : changedLink.source);
        const tgtId = changedLink.target_agent_id || (typeof changedLink.target === 'object' ? changedLink.target.id : changedLink.target);
        const sourceAgent = topology.agents.find((a) => a.id === srcId);
        const targetAgent = topology.agents.find((a) => a.id === tgtId);

        const sName = sourceAgent ? (sourceAgent.name || sourceAgent.hostname) : srcId;
        const tName = targetAgent ? (targetAgent.name || targetAgent.hostname) : tgtId;

        if (!changedLink.isActive) {
          addToast(`Link ${linkIdToBreak} DOWN: ${sName} ↔ ${tName}`, 'error');
        } else {
          addToast(`Link ${linkIdToBreak} RESTORED: ${sName} ↔ ${tName}`, 'success');
        }
      }

      await loadData();

      if (selectedFrom && selectedTo) {
        const newPathResult = await findPath(selectedFrom, selectedTo, requiredBandwidth);
        setPathData(newPathResult);

        if (!newPathResult.found) {
          addToast(`No route available between ${selectedFrom} and ${selectedTo}`, 'error');
        } else if (pathData && !pathData.found && newPathResult.found) {
          addToast(`Alternative route calculated!`, 'info');
        }
      }
    } catch (err) {
      addToast(err.message || 'Error updating topology link', 'error');
    }
  };

  return {
    topology,
    loading,
    selectedFrom,
    setSelectedFrom,
    selectedTo,
    setSelectedTo,
    requiredBandwidth,
    setRequiredBandwidth,
    pathData,
    toasts,
    addToast,
    removeToast,
    loadData,
    handleFindPath,
    handleReleasePath,
    handleSimulateFailure,
  };
};

export default useTopology;
