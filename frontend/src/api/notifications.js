// src/api/notifications.js
import api from './api';

export const getNotificationConfigs = async () => {
  try {
    const data = await api.get('/notifications/configs');
    return Array.isArray(data) ? data : [];
  } catch (error) {
    console.error('API Error in getNotificationConfigs:', error);
    return [];
  }
};

export const createNotificationConfig = async (config) => {
  try {
    return await api.post('/notifications/configs', config);
  } catch (error) {
    console.error('API Error in createNotificationConfig:', error);
    throw error;
  }
};

export const getNotificationLogs = async () => {
  try {
    const data = await api.get('/notifications/logs');
    return Array.isArray(data) ? data : [];
  } catch (error) {
    console.error('API Error in getNotificationLogs:', error);
    return [];
  }
};
