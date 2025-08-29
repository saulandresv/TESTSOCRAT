import apiClient from './api';

export class AnalysisService {
  /**
   * Obtener lista de análisis
   */
  static async getAnalyses(params = {}) {
    const response = await apiClient.get('/analysis/', { params });
    return response.data;
  }

  /**
   * Obtener análisis por ID
   */
  static async getAnalysis(id) {
    const response = await apiClient.get(`/analysis/${id}/`);
    return response.data;
  }

  /**
   * Ejecutar análisis manual
   */
  static async runAnalysis(certificateIds, type = 'SSL_TLS') {
    const response = await apiClient.post('/analysis/run_analysis/', {
      certificate_ids: certificateIds,
      tipo: type,
    });
    return response.data;
  }

  /**
   * Obtener estadísticas para dashboard
   */
  static async getDashboardStats() {
    const response = await apiClient.get('/analysis/dashboard_stats/');
    return response.data;
  }

  /**
   * Obtener vulnerabilidades de un análisis
   */
  static async getAnalysisVulnerabilities(id) {
    const response = await apiClient.get(`/analysis/${id}/vulnerabilities/`);
    return response.data;
  }
}

export default AnalysisService;