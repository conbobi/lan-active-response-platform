// src/services/api.js
import axios from 'axios';
import { readSession, requestSignIn, saveSession } from './operatorSession';


const BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api/v1';

const api = axios.create({
    baseURL: BASE_URL,
    timeout: 300000,
    headers: { 'Content-Type': 'application/json' },
});

export const subscribeLoading = () => () => { };

// Interceptor tự động đính kèm Authorization Bearer token nếu đã đăng nhập hoặc có token mạng
api.interceptors.request.use((config) => {
    const token = readSession();
    if (token && !config.headers.Authorization) config.headers.Authorization = `Bearer ${token}`;
    return config;
});

// Interceptor xử lý response và lỗi
api.interceptors.response.use(
    (res) => res.data,
    (err) => {
        const detail = err.response?.data?.detail;
        const message = Array.isArray(detail)
            ? detail.map(item => item.msg).filter(Boolean).join(' · ')
            : detail || err.response?.data?.error || err.message || 'Something went wrong';
        const error = new Error(message);
        // Keep the machine-readable outcome so callers can tell authorization, policy, evidence
        // and Agent availability failures apart (RESPONSE_ROOT_CAUSE.md).
        error.status = err.response?.status;
        error.outcome = err.response?.data?.outcome_code
            || (err.response ? undefined : 'NETWORK_ERROR');
        if (error.status === 401 && err.config?.url !== '/auth/session') {
            const token = readSession();
            if (token && err.config?.headers?.Authorization === `Bearer ${token}`) saveSession('');
            if (!readSession()) requestSignIn(error.outcome === 'SESSION_EXPIRED' ? 'Phiên đã hết hạn.' : 'Cần đăng nhập Dashboard.');
        }
        error.use = err.response?.data?.use;
        error.requestId = err.response?.data?.request_id;
        return Promise.reject(error);
    }
);

export default api;
