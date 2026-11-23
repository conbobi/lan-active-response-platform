// src/hooks/useProcessTree.js
import { useState, useEffect, useCallback, useRef } from 'react';
import { getProcessTree, killProcess } from '../api/process';
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
  const requestId = useRef(0);
  const [now, setNow] = useState(Date.now);

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
    const request = ++requestId.current;
    if (showLoading) setLoading(true);
    setError(null);

    try {
      const treeData = await getProcessTree(targetAgentId);
      if (request !== requestId.current) return;
      setProcessTree(treeData);
      setSuspiciousProcesses(treeData?.flagged_processes || []);
    } catch (err) {
      if (request !== requestId.current) return;
      console.error('Error in useProcessTree fetchData:', err);
      setError(err.message || 'Failed to fetch process tree telemetry');
    } finally {
      if (request === requestId.current) setLoading(false);
    }
  }, [selectedAgentId]);

  const refresh = useCallback(() => fetchData(selectedAgentId, false), [fetchData, selectedAgentId]);
  const resync = useCallback(() => {
    setProcessTree(null);
    refresh();
  }, [refresh]);
  const { isConnected } = useDashboardSocket(useCallback((message) => {
    if (message.type === 'ACTIVITY_UPDATED' && message.stream === 'PROCESS_LIST' && message.agent_id === selectedAgentId) {
      refresh();
    }
  }, [selectedAgentId, refresh]), resync);

  useEffect(() => {
    setProcessTree(null);
    setSuspiciousProcesses([]);
    fetchData(selectedAgentId);
    const fallback = setInterval(refresh, 60000);
    const tick = setInterval(() => setNow(Date.now()), 1000);
    return () => {
      requestId.current++;
      clearInterval(tick);
      clearInterval(fallback);
    };
  }, [selectedAgentId, fetchData, refresh]);

  const processLive = isConnected && !error && processTree?.observation?.status === 'running' &&
    Date.parse(processTree.observation.expires_at) > now;

  const queueTermination = async ({ pid, reason, killTree, target }) => {
    if (!processLive) throw new Error('Process observation is stale. Refresh before sending a response.');
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
    suspiciousProcesses: processLive ? suspiciousProcesses : [],
    processLive,
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
