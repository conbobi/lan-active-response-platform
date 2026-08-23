// src/api/whitelist.js
import api from './api';

export const getWhitelist = async () => {
  try {
    const data = await api.get('/whitelist');
    return Array.isArray(data) ? data : [];
  } catch (error) {
    console.error('API Error in getWhitelist:', error);
    return [];
  }
};

export const addWhitelistEntry = async (entry) => {
  try {
    return await api.post('/whitelist', entry);
  } catch (error) {
    console.error('API Error in addWhitelistEntry:', error);
    throw error;
  }
};

export const removeWhitelistEntry = async (entryId) => {
  try {
    return await api.delete(`/whitelist/${entryId}`);
  } catch (error) {
    console.error(`API Error removing whitelist entry ${entryId}:`, error);
    throw error;
  }
};
