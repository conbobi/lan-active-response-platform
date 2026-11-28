// src/api/api.js
import axios from 'axios';
import {
  clearAuthSession,
  readSession,
  requestSignIn,
  saveAuthSession,
} from './operatorSession.js';

export const BASE_URL = import.meta.env?.VITE_API_BASE_URL || '/api/v1';

const api = axios.create({
  baseURL: BASE_URL,
  timeout: 300000,
  withCredentials: true,
  headers: { 'Content-Type': 'application/json' },
});

export const subscribeLoading = () => () => {};

let refreshInFlight = null;

function isAuthLifecyclePath(url = '') {
  return (
    url.includes('/auth/login') ||
    url.includes('/auth/refresh') ||
    url.includes('/auth/logout') ||
    url.includes('/auth/session')
  );
}

export function refreshAccessToken() {
  if (refreshInFlight) return refreshInFlight;
  refreshInFlight = api
    .post(
      '/auth/refresh',
      {},
      {
        headers: { 'X-LARP-CSRF': '1' },
        _skipAuthHeader: true,
        _skipAuthRefresh: true,
      }
    )
    .then((res) => {
      if (res?.access_token) {
        saveAuthSession(res);
        return res.access_token;
      }
      clearAuthSession();
      return null;
    })
    .catch(() => {
      clearAuthSession();
      return null;
    })
    .finally(() => {
      refreshInFlight = null;
    });
  return refreshInFlight;
}

export function bootstrapAuth() {
  if (readSession()) return Promise.resolve(readSession());
  return refreshAccessToken();
}

export async function loginWithPassword(username, password) {
  const res = await api.post(
    '/auth/login',
    { username, password },
    { _skipAuthHeader: true, _skipAuthRefresh: true }
  );
  saveAuthSession(res);
  return res;
}

export async function logoutSession(allDevices = false) {
  try {
    await api.post(
      allDevices ? '/auth/logout-all' : '/auth/logout',
      {},
      {
        headers: { 'X-LARP-CSRF': '1' },
        _skipAuthRefresh: true,
      }
    );
  } catch {
    // Clear local memory state even if cookie was already absent or expired.
  } finally {
    clearAuthSession();
  }
}

// Attach in-memory JWT Bearer access token to API requests.
api.interceptors.request.use((config) => {
  if (config._skipAuthHeader) return config;
  const token = readSession();
  if (token && !config.headers.Authorization) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Single-flight refresh + single retry on 401; structured outcome propagation otherwise.
api.interceptors.response.use(
  (res) => res.data,
  async (err) => {
    const config = err.config;
    if (
      err.response?.status === 401 &&
      config &&
      !config._retried &&
      !config._skipAuthRefresh &&
      !isAuthLifecyclePath(config.url || '')
    ) {
      config._retried = true;
      const nextToken = await refreshAccessToken();
      if (nextToken) {
        config.headers = config.headers || {};
        config.headers.Authorization = `Bearer ${nextToken}`;
        return api.request(config);
      }
    }

    const detail = err.response?.data?.detail;
    const message = Array.isArray(detail)
      ? detail.map((item) => item.msg).filter(Boolean).join(' · ')
      : detail || err.response?.data?.error || err.message || 'Something went wrong';
    const error = new Error(message);
    error.status = err.response?.status;
    error.outcome =
      err.response?.data?.outcome_code || (err.response ? undefined : 'NETWORK_ERROR');

    if (error.status === 401 && !isAuthLifecyclePath(config?.url || '')) {
      clearAuthSession();
      requestSignIn(
        error.outcome === 'SESSION_EXPIRED'
          ? 'Phiên đã hết hạn.'
          : 'Cần đăng nhập Dashboard.'
      );
    }

    error.use = err.response?.data?.use;
    error.requestId = err.response?.data?.request_id;
    return Promise.reject(error);
  }
);

export default api;
