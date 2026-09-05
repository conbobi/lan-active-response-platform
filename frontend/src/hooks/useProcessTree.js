// src/hooks/useProcessTree.js
import { useState, useEffect, useCallback, useRef } from 'react';
import { getProcessTree, getSuspiciousProcesses, killProcess, killProcessTree } from '../api/process';
import { useDashboardSocket } from './useDashboardSocket';

// Helper to optimistically remove killed nodes from process tree hierarchy
const filterTreeNodes = (nodes, targetPid) => {
  if (!Array.isArray(nodes)) return [];
  return nodes
    .filter((node) => node && Number(node.pid) !== Number(targetPid))
    .map((node) => ({
      ...node,
      children: Array.isArray(node.children) ? filterTreeNodes(node.children, targetPid) : []
    }));
};

export const useProcessTree = (agentId = '') => {
  const [selectedAgentId, setSelectedAgentId] = useState(agentId);
  const [processTree, setProcessTree] = useState(null);
  const [suspiciousProcesses, setSuspiciousProcesses] = useState([]);
  const [loading, setLoading] = useState(false);
  const [killing, setKilling] = useState(false);
  const [error, setError] = useState(null);
  const [actionSuccess, setActionSuccess] = useState(null);

  const killTimerRef = useRef(null);

  // Clear any pending timeout on unmount
  useEffect(() => {
    return () => {
      if (killTimerRef.current) {
        clearTimeout(killTimerRef.current);
      }
    };
  }, []);

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

  // Initial fetch and auto-polling every 10 seconds
  useEffect(() => {
    if (selectedAgentId) {
      fetchData(selectedAgentId, true);

      const interval = setInterval(() => {
        fetchData(selectedAgentId, false);
      }, 10000);

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
    setError(null);
    setActionSuccess(null);

    try {
      await killProcess(targetAgent, pid, false);

      // Optimistically remove from local suspicious list & tree
      setSuspiciousProcesses((prev) => prev.filter((p) => Number(p.pid) !== Number(pid)));
      setProcessTree((prev) => {
        if (!prev) return prev;
        const roots = prev.tree || (Array.isArray(prev) ? prev : [prev]);
        const updated = filterTreeNodes(roots, pid);
        return prev.tree ? { ...prev, tree: updated } : updated;
      });

      setActionSuccess(`Kill signal dispatched for PID ${pid}`);

      // Delay 1500ms before refreshing to allow agent execution and manager telemetry sync
      if (killTimerRef.current) clearTimeout(killTimerRef.current);
      killTimerRef.current = setTimeout(async () => {
        try {
          await fetchData(targetAgent, false);
        } finally {
          setKilling(false);
        }
      }, 1500);

      return true;
    } catch (err) {
      console.error(`Kill process PID ${pid} error:`, err);
      setError(err?.response?.data?.detail || err.message || `Failed to kill process PID ${pid}`);
      setKilling(false);
      throw err;
    }
  };

  const handleKillProcessTree = async (pid, processName = null) => {
    const targetAgent = selectedAgentId || agentId;
    if (!targetAgent || !pid) return;

    setKilling(true);
    setError(null);
    setActionSuccess(null);

    try {
      await killProcessTree(targetAgent, pid, processName);

      // Optimistically remove from local suspicious list & tree
      setSuspiciousProcesses((prev) => prev.filter((p) => Number(p.pid) !== Number(pid)));
      setProcessTree((prev) => {
        if (!prev) return prev;
        const roots = prev.tree || (Array.isArray(prev) ? prev : [prev]);
        const updated = filterTreeNodes(roots, pid);
        return prev.tree ? { ...prev, tree: updated } : updated;
      });

      setActionSuccess(`Kill Tree signal dispatched for PID ${pid} (${processName || 'process tree'})`);

      // Delay 1500ms before refreshing to allow agent execution and manager telemetry sync
      if (killTimerRef.current) clearTimeout(killTimerRef.current);
      killTimerRef.current = setTimeout(async () => {
        try {
          await fetchData(targetAgent, false);
        } finally {
          setKilling(false);
        }
      }, 1500);

      return true;
    } catch (err) {
      console.error(`Kill process tree PID ${pid} error:`, err);
      setError(err?.response?.data?.detail || err.message || `Failed to kill process tree PID ${pid}`);
      setKilling(false);
      throw err;
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
    actionSuccess,
    clearActionSuccess: () => setActionSuccess(null),
    clearError: () => setError(null),
    fetchData: () => fetchData(selectedAgentId, true),
    refreshProcessData: () => fetchData(selectedAgentId, true),
    handleKillProcess,
    handleKillProcessTree,
  };
};

export default useProcessTree;
