import apiClient from './api';

export class CertificateService {
  /**
   * Obtener lista de certificados
   */
  static async getCertificates(params = {}) {
    const response = await apiClient.get('http://localhost:8000/api/certs/certificates/', { params });
    return response.data;
  }

  /**
   * Obtener certificado por ID
   */
  static async getCertificate(id) {
    const response = await apiClient.get(`/certificates/${id}/`);
    return response.data;
  }

  /**
   * Crear certificado
   */
  static async createCertificate(data) {
    const response = await apiClient.post('/certificates/', data);
    return response.data;
  }

  /**
   * Actualizar certificado
   */
  static async updateCertificate(id, data) {
    const response = await apiClient.patch(`/certificates/${id}/`, data);
    return response.data;
  }

  /**
   * Eliminar certificado
   */
  static async deleteCertificate(id) {
    const response = await apiClient.delete(`/certificates/${id}/`);
    return response.data;
  }

  /**
   * Verificar vitalidad manualmente
   */
  static async checkVitality(id) {
    const response = await apiClient.post(`/certificates/${id}/check_vitality/`);
    return response.data;
  }

  /**
   * Obtener historial de vitalidad
   */
  static async getVitalityHistory(id, params = {}) {
    const response = await apiClient.get(`/certificates/${id}/vitality/`, { params });
    return response.data;
  }
}

export default CertificateService;