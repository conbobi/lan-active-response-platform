// src/hooks/useFlows.js
import { useState, useEffect } from 'react';
import { getFlows } from '../api/flows';

export const useFlows = () => {
  const [flows, setFlows] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchFlows = async () => {
    setLoading(true);
    try {
      const data = await getFlows();
      setFlows(data);
    } catch (e) {
      console.error('Failed to fetch flows', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFlows();
    const interval = setInterval(fetchFlows, 5000);
    return () => clearInterval(interval);
  }, []);

  return { flows, loading };
};
