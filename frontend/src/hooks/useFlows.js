// src/hooks/useFlows.js
import { useState, useEffect, useCallback } from 'react';
import { getFlows } from '../api/flows';

export const useFlows = (agentId = 'all') => {
  const [flows, setFlows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchFlows = useCallback(async () => {
    try {
      const params = agentId && agentId !== 'all' ? { agent_id: agentId } : {};
      const data = await getFlows(params);
      setFlows(Array.isArray(data) ? data : []);
      setError(null);
    } catch (e) {
      console.error('Failed to fetch flows', e);
      setError(e.message || 'Failed to fetch flows');
    } finally {
      setLoading(false);
    }
  }, [agentId]);

  useEffect(() => {
    fetchFlows();
    const interval = setInterval(fetchFlows, 4000);
    return () => clearInterval(interval);
  }, [fetchFlows]);

  return { flows, loading, error, refresh: fetchFlows };
};

export default useFlows;
