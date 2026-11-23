// src/hooks/useProcessTree.js
import { useState, useEffect, useCallback, useRef } from 'react';
import { getProcessTree, getSuspiciousProcesses, killProcess } from '../api/process';
import { useDashboardSocket } from './useDashboardSocket';

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

  // Initial fetch and auto-polling every 30 seconds
  useEffect(() => {
    if (selectedAgentId) {
      fetchData(selectedAgentId, true);

      const interval = setInterval(() => {
        fetchData(selectedAgentId, false);
      }, 30000);

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

  const queueTermination = async ({ pid, reason, killTree, target }) => {
    setKilling(true);
    setError(null);
    try {
      const action = await killProcess(selectedAgentId || agentId, pid, {
        reason, killTree, target, confirmed: true,
      });
      setActionSuccess(`Đã gửi yêu cầu cho PID ${pid}. Đang chờ Agent xác minh.`);
      if (killTimerRef.current) clearTimeout(killTimerRef.current);
      killTimerRef.current = setTimeout(() => fetchData(selectedAgentId || agentId, false), 1500);
      return action;
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
    actionSuccess,
    clearActionSuccess: () => setActionSuccess(null),
    clearError: () => setError(null),
    fetchData: () => fetchData(selectedAgentId, true),
    refreshProcessData: () => fetchData(selectedAgentId, true),
    queueTermination,
  };
};

export default useProcessTree;
