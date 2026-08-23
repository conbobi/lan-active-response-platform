// src/api/settings.js
import api from './api';

export const getSettings = async () => {
  try {
    const data = await api.get('/settings');
    return data;
  } catch (error) {
    console.error('API Error in getSettings:', error);
    return null;
  }
};

export const getSettingByKey = async (key) => {
  try {
    return await api.get(`/settings/${key}`);
  } catch (error) {
    console.error(`API Error in getSettingByKey (${key}):`, error);
    return null;
  }
};

export const updateSetting = async (key, value) => {
  try {
    return await api.put(`/settings/${key}`, { value });
  } catch (error) {
    console.error(`API Error updating setting ${key}:`, error);
    throw error;
  }
};
