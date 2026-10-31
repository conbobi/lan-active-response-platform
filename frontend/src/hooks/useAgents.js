// src/hooks/useAgents.js
import { useState, useEffect, useCallback } from 'react';
import toast from 'react-hot-toast';
import { getAgents, isolateAgent, unisolateAgent } from '../api/agents';

export const useAgents = ({ autoRefresh = true, refreshInterval = 5000 } = {}) => {
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchAgents = useCallback(async () => {
    try {
      const data = await getAgents();
      setAgents(Array.isArray(data) ? data : []);
      setError(null);
    } catch (e) {
      console.error('Failed to fetch agents', e);
      setError(e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAgents();
    if (!autoRefresh) return;
    const interval = setInterval(fetchAgents, refreshInterval);
    return () => clearInterval(interval);
  }, [fetchAgents, autoRefresh, refreshInterval]);

  const handleIsolate = async (agentId) => {
    try {
      await isolateAgent(agentId);
      toast.success(`Đã cô lập mạng cho agent ${agentId}`);
      await fetchAgents();
    } catch (e) {
      console.error('Failed to isolate agent', e);
      toast.error(`Cô lập agent thất bại: ${e.response?.data?.detail || e.message}`);
    }
  };

  const handleUnisolate = async (agentId) => {
    try {
      await unisolateAgent(agentId);
      toast.success(`Đã hủy cô lập cho agent ${agentId}`);
      await fetchAgents();
    } catch (e) {
      console.error('Failed to release agent', e);
      toast.error(`Hủy cô lập thất bại: ${e.response?.data?.detail || e.message}`);
    }
  };

  return {
    agents,
    loading,
    error,
    refresh: fetchAgents,
    fetchAgents,
    refetch: fetchAgents,
    refreshAgents: fetchAgents,
    handleIsolate,
    handleUnisolate
  };
};

