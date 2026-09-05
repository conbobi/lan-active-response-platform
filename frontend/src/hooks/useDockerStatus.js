import { useState, useEffect, useCallback } from 'react';
import { getDockerStatus } from '../api/docker';

export const useDockerStatus = () => {
  const [containers, setContainers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchDockerStatus = useCallback(async () => {
    try {
      const data = await getDockerStatus();
      setContainers(Array.isArray(data) ? data : data?.containers || []);
      setError(null);
    } catch (err) {
      console.error('Failed to fetch Docker status:', err);
      setError(err.message || 'Cannot connect to Docker daemon');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchDockerStatus();
    const interval = setInterval(fetchDockerStatus, 5000); // Poll every 5s
    return () => clearInterval(interval);
  }, [fetchDockerStatus]);

  return {
    containers,
    loading,
    error,
    refresh: fetchDockerStatus,
    fetchDockerStatus,
  };
};

export default useDockerStatus;
