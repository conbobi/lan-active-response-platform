// src/api/threatIntel.js
import api from './api';

export const checkThreatIndicator = async (indicatorType, value) => {
  try {
    return await api.post('/threat-intel/check', {
      indicator_type: indicatorType,
      value: value,
    });
  } catch (error) {
    console.error('API Error in checkThreatIndicator:', error);
    throw error;
  }
};
