// src/services/api.js
import axios from 'axios';

export const DEFAULT_SOC_ADMIN_TOKEN = 'larp-token-soc-admin-3bcddf770e95f201fa77f157d9d4ab6237a63fd16098c2eb';
export const DEFAULT_LEGACY_ADMIN_TOKEN = 'larp-token-legacy-admin-2febe999daaf1ed95d24fae3cc447aa12096d42092573f87';

const BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api/v1';

const api = axios.create({
    baseURL: BASE_URL,
    timeout: 300000,
    headers: { 'Content-Type': 'application/json' },
});

export const subscribeLoading = () => () => { };

// Attach auth token if available (or use default SOC token for seamless operations)
api.interceptors.request.use((config) => {
    const token = localStorage.getItem('larp_network_token') || DEFAULT_SOC_ADMIN_TOKEN;
    if (token && !config.headers.Authorization) {
        config.headers.Authorization = `Bearer ${token}`;
    }
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
        return Promise.reject(new Error(message));
    }
);

export default api;