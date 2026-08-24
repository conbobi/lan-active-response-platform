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

export const getRiskThresholds = async () => {
  try {
    return await api.get('/settings/risk_thresholds');
  } catch (error) {
    console.error('API Error in getRiskThresholds:', error);
    return { auto_isolate: 85, alert_with_buttons: 70, alert: 50, log: 20 };
  }
};

export const updateRiskThresholds = async (thresholds) => {
  return await api.put('/settings/risk_thresholds', thresholds);
};

export const getFileChangesThresholds = async () => {
  try {
    return await api.get('/settings/file_changes_thresholds');
  } catch (error) {
    console.error('API Error in getFileChangesThresholds:', error);
    return { file_changes_critical: 100, file_changes_elevated: 30 };
  }
};

export const updateFileChangesThresholds = async (thresholds) => {
  return await api.put('/settings/file_changes_thresholds', thresholds);
};
