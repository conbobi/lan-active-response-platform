// src/api/reports.js
import api from './api';

export const getReports = async () => {
  try {
    const data = await api.get('/reports');
    return Array.isArray(data) ? data : [];
  } catch (error) {
    console.error('API Error in getReports:', error);
    return [];
  }
};

export const generateReport = async (payload) => {
  try {
    return await api.post('/reports/generate', payload);
  } catch (error) {
    console.error('API Error in generateReport:', error);
    throw error;
  }
};

export const downloadReport = async (reportId) => {
  try {
    const baseURL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8002/api/v1';
    window.open(`${baseURL}/reports/${reportId}/download`, '_blank');
  } catch (error) {
    console.error(`API Error downloading report ${reportId}:`, error);
  }
};
