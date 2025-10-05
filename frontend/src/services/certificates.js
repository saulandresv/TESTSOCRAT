import axios from 'axios';

// Cliente específico para certificados
const certsClient = axios.create({
  baseURL: '/api/certs',  // Usar proxy de Vite
  timeout: 60000,
});

// Interceptor para agregar token
certsClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('access_token');
    console.log('🔐 Certificate request interceptor:');
    console.log('  - URL:', config.baseURL + config.url);
    console.log('  - Method:', config.method?.toUpperCase());
    console.log('  - Token:', token ? 'EXISTS (length=' + token.length + ')' : 'MISSING');
    console.log('  - Data:', config.data);

    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
      console.log('  - Added Authorization header');
    }
    return config;
  },
  (error) => {
    console.error('❌ Request interceptor error:', error);
    return Promise.reject(error);
  }
);

// Interceptor para manejar respuestas
certsClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      console.error('Token expirado, redirigir al login');
      // Aquí podrías dispatch un logout o redirigir
    }
    return Promise.reject(error);
  }
);

export class CertificateService {
  /**
   * Obtener lista de certificados
   */
  static async getCertificates(params = {}) {
    try {
      const response = await certsClient.get('/certificates/', { params });
      return response.data;
    } catch (error) {
      console.error('Certificate service error:', error);
      throw error;
    }
  }

  /**
   * Obtener certificado por ID
   */
  static async getCertificate(id) {
    try {
      const response = await certsClient.get(`/certificates/${id}/`);
      return response.data;
    } catch (error) {
      console.error('Certificate service error:', error);
      throw error;
    }
  }

  /**
   * Crear certificado
   */
  static async createCertificate(data) {
    try {
      console.log('🚀 Creating certificate with data:', data);
      console.log('🔑 Token in localStorage:', localStorage.getItem('access_token') ? 'EXISTS' : 'MISSING');

      const response = await certsClient.post('/certificates/', data);
      console.log('✅ Certificate created successfully:', response.data);
      return response.data;
    } catch (error) {
      console.error('❌ Certificate creation error:', error);
      console.error('❌ Error response:', error.response?.data);
      console.error('❌ Error status:', error.response?.status);
      console.error('❌ Error headers:', error.response?.headers);
      throw error;
    }
  }

  /**
   * Actualizar certificado
   */
  static async updateCertificate(id, data) {
    try {
      const response = await certsClient.patch(`/certificates/${id}/`, data);
      return response.data;
    } catch (error) {
      console.error('Certificate service error:', error);
      throw error;
    }
  }

  /**
   * Eliminar certificado
   */
  static async deleteCertificate(id) {
    try {
      const response = await certsClient.delete(`/certificates/${id}/`);
      return response.data;
    } catch (error) {
      console.error('Certificate service error:', error);
      throw error;
    }
  }

  /**
   * Verificar vitalidad manualmente
   */
  static async checkVitality(id) {
    try {
      const response = await certsClient.post(`/certificates/${id}/check_vitality/`);
      return response.data;
    } catch (error) {
      console.error('Certificate service error:', error);
      throw error;
    }
  }

  /**
   * Obtener historial de vitalidad
   */
  static async getVitalityHistory(id, params = {}) {
    try {
      const response = await certsClient.get(`/certificates/${id}/vitality/`, { params });
      return response.data;
    } catch (error) {
      console.error('Certificate service error:', error);
      throw error;
    }
  }
}

export default CertificateService;