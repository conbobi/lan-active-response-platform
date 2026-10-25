// src/services/api.js
import axios from 'axios';

const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8005/api/v1';

const api = axios.create({
    baseURL: BASE_URL,
    headers: { 'Content-Type': 'application/json' },
});

export const subscribeLoading = () => () => {};

// Interceptor xử lý response và lỗi
api.interceptors.response.use(
    (res) => res.data,
    (err) => {
        const message = err.response?.data?.detail || err.response?.data?.error || err.message || 'Something went wrong';
        return Promise.reject(new Error(message));
    }
);

export default api;