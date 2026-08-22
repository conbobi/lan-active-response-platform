// src/hooks/useAgents.js
import { useState, useEffect, useCallback } from 'react';
import { getAgents, isolateAgent, unisolateAgent } from '../api/agents';

export const useAgents = () => {
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchAgents = useCallback(async () => {
    try {
      const data = await getAgents();
      setAgents(data);
    } catch (e) {
      console.error('Failed to fetch agents', e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAgents();
    const interval = setInterval(fetchAgents, 5000); // every 5 seconds
    return () => clearInterval(interval);
  }, [fetchAgents]);

  const handleIsolate = async (agentId) => {
    try {
      await isolateAgent(agentId);
      await fetchAgents();
    } catch (e) {
      console.error('Failed to isolate agent', e);
    }
  };

  const handleUnisolate = async (agentId) => {
    try {
      await unisolateAgent(agentId);
      await fetchAgents();
    } catch (e) {
      console.error('Failed to release agent', e);
    }
  };

  return { agents, loading, fetchAgents, refetch: fetchAgents, refreshAgents: fetchAgents, handleIsolate, handleUnisolate };
};
