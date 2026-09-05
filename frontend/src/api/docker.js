import api from './api';

/**
 * Fetch real-time status and resource usage of all Docker containers.
 * @returns {Promise<Array>} List of containers with status and resource metrics
 */
export const getDockerStatus = async () => {
  const response = await api.get('/docker/status');
  return response;
};
