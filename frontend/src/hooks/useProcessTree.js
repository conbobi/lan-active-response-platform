// src/hooks/useProcessTree.js
import { useState, useEffect, useCallback } from 'react';
import { getProcessTree, getSuspiciousProcesses, killProcess, killProcessTree } from '../api/process';
import { useDashboardSocket } from './useDashboardSocket';

export const useProcessTree = (agentId = '') => {
  const [selectedAgentId, setSelectedAgentId] = useState(agentId);
  const [processTree, setProcessTree] = useState(null);
  const [suspiciousProcesses, setSuspiciousProcesses] = useState([]);
  const [loading, setLoading] = useState(false);
  const [killing, setKilling] = useState(false);
  const [error, setError] = useState(null);

  // Sync internal selectedAgentId if passed agentId changes from outside
  useEffect(() => {
    if (agentId) {
      setSelectedAgentId(agentId);
    }
  }, [agentId]);

  const fetchData = useCallback(async (targetAgentId = selectedAgentId, showLoading = true) => {
    if (!targetAgentId) return;
    if (showLoading) setLoading(true);
    setError(null);

    try {
      const [treeData, suspiciousData] = await Promise.all([
        getProcessTree(targetAgentId).catch((err) => {
          console.warn(`Failed to fetch process tree for ${targetAgentId}:`, err);
          return null;
        }),
        getSuspiciousProcesses(targetAgentId).catch((err) => {
          console.warn(`Failed to fetch suspicious processes for ${targetAgentId}:`, err);
          return [];
        }),
      ]);

      setProcessTree(treeData);
      setSuspiciousProcesses(Array.isArray(suspiciousData) ? suspiciousData : []);
    } catch (err) {
      console.error('Error in useProcessTree fetchData:', err);
      setError(err.message || 'Failed to fetch process tree telemetry');
    } finally {
      if (showLoading) setLoading(false);
    }
  }, [selectedAgentId]);

  // Initial fetch and auto-polling every 5 seconds
  useEffect(() => {
    if (selectedAgentId) {
      fetchData(selectedAgentId, true);

      const interval = setInterval(() => {
        fetchData(selectedAgentId, false);
      }, 5000);

      return () => clearInterval(interval);
    }
  }, [selectedAgentId, fetchData]);

  // Realtime WebSocket updates if PROCESS_LIST arrives for this agent
  useDashboardSocket(
    useCallback((msg) => {
      if (msg && (msg.type === 'PROCESS_LIST' || msg.type === 'TELEMETRY_RISK')) {
        const msgAgentId = msg.payload?.agent_id || msg.agent_id;
        if (!selectedAgentId || msgAgentId === selectedAgentId) {
          fetchData(selectedAgentId, false);
        }
      }
    }, [selectedAgentId, fetchData])
  );

  const handleKillProcess = async (pid) => {
    const targetAgent = selectedAgentId || agentId;
    if (!targetAgent || !pid) return;
    setKilling(true);
    try {
      await killProcess(targetAgent, pid, false);
      await fetchData(targetAgent, false);
    } catch (err) {
      console.warn(`Kill process PID ${pid} fallback local UI update`);
      setSuspiciousProcesses((prev) => prev.filter((p) => p.pid !== pid));
    } finally {
      setKilling(false);
    }
  };

  const handleKillProcessTree = async (pid, processName = null) => {
    const targetAgent = selectedAgentId || agentId;
    if (!targetAgent || !pid) return;
    setKilling(true);
    try {
      await killProcess(targetAgent, pid, true, processName);
      await fetchData(targetAgent, false);
    } catch (err) {
      console.warn(`Kill process tree PID ${pid} fallback local UI update`);
      setSuspiciousProcesses((prev) => prev.filter((p) => p.pid !== pid));
    } finally {
      setKilling(false);
    }
  };

  return {
    selectedAgentId,
    setSelectedAgentId,
    processTree,
    suspiciousProcesses,
    loading,
    killing,
    error,
    fetchData: () => fetchData(selectedAgentId, true),
    refreshProcessData: () => fetchData(selectedAgentId, true),
    handleKillProcess,
    handleKillProcessTree,
  };
};

export default useProcessTree;
