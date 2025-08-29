import apiClient from './api';

export class ReportService {
  /**
   * Generar reporte de certificados
   */
  static async generateCertificateReport(data) {
    const response = await apiClient.post('/reports/certificates/', data);
    return response.data;
  }

  /**
   * Obtener estado de un reporte
   */
  static async getReportStatus(jobId) {
    const response = await apiClient.get(`/reports/${jobId}/`);
    return response.data;
  }

  /**
   * Obtener historial de reportes
   */
  static async getReportHistory(params = {}) {
    const response = await apiClient.get('/reports/history/', { params });
    return response.data;
  }

  /**
   * Descargar reporte
   */
  static async downloadReport(jobId) {
    const response = await apiClient.get(`/reports/${jobId}/download/`, {
      responseType: 'blob'
    });
    return response.data;
  }

  /**
   * Obtener lista de clientes para filtros
   */
  static async getClients() {
    const response = await apiClient.get('/clients/');
    return response.data;
  }
}

export default ReportService;