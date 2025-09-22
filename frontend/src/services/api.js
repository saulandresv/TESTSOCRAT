import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1';

// Crear instancia de axios
const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Interceptor para agregar token JWT
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('access_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Interceptor para manejar respuestas
apiClient.interceptors.response.use(
  (response) => {
    return response;
  },
  async (error) => {
    const originalRequest = error.config;

    console.log('🌐 API Error interceptor triggered:', {
      status: error.response?.status,
      url: originalRequest?.url,
      method: originalRequest?.method
    });

    // Si el token ha expirado (401) y tenemos refresh token
    if (error.response?.status === 401 && !originalRequest._retry) {
      console.log('🌐 401 detected, attempting refresh...');

      // SKIP refresh for MFA endpoints - they don't require authentication
      if (originalRequest?.url?.includes('/auth/mfa/verify/') ||
          originalRequest?.url?.includes('/auth/login/')) {
        console.log('🌐 Skipping refresh for auth endpoint');
        return Promise.reject(error);
      }

      originalRequest._retry = true;

      const refreshToken = localStorage.getItem('refresh_token');
      if (refreshToken) {
        try {
          console.log('🌐 Attempting token refresh...');
          const response = await axios.post(`${API_BASE_URL}/auth/refresh/`, {
            refresh: refreshToken,
          });

          const { access } = response.data;
          localStorage.setItem('access_token', access);

          // Reintentar la petición original
          originalRequest.headers.Authorization = `Bearer ${access}`;
          console.log('🌐 Token refreshed, retrying original request');
          return apiClient(originalRequest);
        } catch (refreshError) {
          console.log('🌐 Refresh failed, redirecting to login');
          // Si el refresh falla, redirigir al login
          localStorage.removeItem('access_token');
          localStorage.removeItem('refresh_token');
          localStorage.removeItem('user');
          window.location.href = '/login';
          return Promise.reject(refreshError);
        }
      } else {
        console.log('🌐 No refresh token, redirecting to login');
        // No hay refresh token, redirigir al login
        window.location.href = '/login';
      }
    }

    return Promise.reject(error);
  }
);

export default apiClient;