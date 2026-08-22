// src/api/path.js
import api from './api';

export const requestPath = async (payload) => {
  return await api.post('/path/request', payload);
};

export const releasePath = async (payload) => {
  return await api.post('/path/release', payload);
};
