import React, { useState, useEffect } from 'react';
import Layout from './Layout';
import { ReportService } from '../services/reports';
import { AuthService } from '../services/auth';

const Reports = () => {
  const [reports, setReports] = useState([]);
  const [clients, setClients] = useState([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [showGenerateModal, setShowGenerateModal] = useState(false);
  const [formData, setFormData] = useState({
    client_id: '',
    report_type: 'CERTIFICATE_SUMMARY',
    format: 'PDF',
    filters: {
      protocol: '',
      expires_within_days: '',
      include_inactive: false
    }
  });

  useEffect(() => {
    loadInitialData();
  }, []);

  const loadInitialData = async () => {
    try {
      setLoading(true);
      const [reportsResponse, clientsResponse] = await Promise.all([
        ReportService.getReportHistory(),
        ReportService.getClients()
      ]);

      setReports(reportsResponse.results || reportsResponse);
      setClients(clientsResponse.results || clientsResponse);
    } catch (error) {
      console.error('Error loading data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateReport = async (e) => {
    e.preventDefault();
    setGenerating(true);

    try {
      const reportData = {
        client_id: formData.client_id || null,
        type: formData.report_type,
        format: formData.format,
        filters: formData.filters
      };

      const response = await ReportService.generateCertificateReport(reportData);
      
      // Agregar el nuevo reporte a la lista
      setReports(prev => [response, ...prev]);
      
      setShowGenerateModal(false);
      setFormData({
        client_id: '',
        report_type: 'CERTIFICATE_SUMMARY',
        format: 'PDF',
        filters: {
          protocol: '',
          expires_within_days: '',
          include_inactive: false
        }
      });

      alert('Reporte generado exitosamente. Se está procesando...');
    } catch (error) {
      console.error('Error generating report:', error);
      alert('Error al generar reporte');
    } finally {
      setGenerating(false);
    }
  };

  const handleDownload = async (reportId, filename) => {
    try {
      const blob = await ReportService.downloadReport(reportId);
      
      // Crear URL para descarga
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename || `report_${reportId}.pdf`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Error downloading report:', error);
      alert('Error al descargar reporte');
    }
  };

  const refreshReportStatus = async (reportId) => {
    try {
      const updatedReport = await ReportService.getReportStatus(reportId);
      setReports(prev => prev.map(report => 
        report.id === reportId ? updatedReport : report
      ));
    } catch (error) {
      console.error('Error refreshing report status:', error);
    }
  };

  const getStatusColor = (status) => {
    const colors = {
      'PENDING': '#f59e0b',
      'PROCESSING': '#3b82f6',
      'COMPLETED': '#059669',
      'FAILED': '#dc2626'
    };
    return colors[status] || '#6b7280';
  };

  const getStatusIcon = (status) => {
    const icons = {
      'PENDING': '⏳',
      'PROCESSING': '🔄',
      'COMPLETED': '✅',
      'FAILED': '❌'
    };
    return icons[status] || '❓';
  };

  const formatFileSize = (bytes) => {
    if (!bytes) return 'N/A';
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleString('es-CL');
  };

  if (loading) {
    return (
      <Layout>
        <div style={{ textAlign: 'center', padding: '2rem' }}>
          <div style={{ fontSize: '1.5rem' }}>🔄</div>
          <p>Cargando reportes...</p>
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div style={{ maxWidth: '1400px', margin: '0 auto' }}>
        {/* Header */}
        <div style={{ 
          display: 'flex', 
          justifyContent: 'space-between', 
          alignItems: 'center',
          marginBottom: '2rem'
        }}>
          <div>
            <h2 style={{ fontSize: '1.875rem', fontWeight: 'bold', color: '#1f2937', margin: 0 }}>
              📄 Reportes
            </h2>
            <p style={{ color: '#6b7280', margin: '0.5rem 0 0 0' }}>
              Generación y descarga de reportes de certificados
            </p>
          </div>
          
          <button
            onClick={() => setShowGenerateModal(true)}
            style={{
              padding: '0.75rem 1.5rem',
              backgroundColor: '#4f46e5',
              color: 'white',
              border: 'none',
              borderRadius: '0.5rem',
              cursor: 'pointer',
              fontWeight: '500',
              fontSize: '0.875rem'
            }}
          >
            ➕ Generar Reporte
          </button>
        </div>

        {/* Estadísticas rápidas */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '1.5rem',
          marginBottom: '2rem'
        }}>
          <div style={{
            backgroundColor: 'white',
            padding: '1.5rem',
            borderRadius: '0.5rem',
            boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
            textAlign: 'center'
          }}>
            <div style={{ fontSize: '2rem', fontWeight: 'bold', color: '#4f46e5' }}>
              {reports.length}
            </div>
            <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>
              Total Reportes
            </div>
          </div>
          
          <div style={{
            backgroundColor: 'white',
            padding: '1.5rem',
            borderRadius: '0.5rem',
            boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
            textAlign: 'center'
          }}>
            <div style={{ fontSize: '2rem', fontWeight: 'bold', color: '#059669' }}>
              {reports.filter(r => r.status === 'COMPLETED').length}
            </div>
            <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>
              Completados
            </div>
          </div>
          
          <div style={{
            backgroundColor: 'white',
            padding: '1.5rem',
            borderRadius: '0.5rem',
            boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
            textAlign: 'center'
          }}>
            <div style={{ fontSize: '2rem', fontWeight: 'bold', color: '#f59e0b' }}>
              {reports.filter(r => r.status === 'PROCESSING' || r.status === 'PENDING').length}
            </div>
            <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>
              En Proceso
            </div>
          </div>
        </div>

        {/* Lista de reportes */}
        <div style={{
          backgroundColor: 'white',
          borderRadius: '0.5rem',
          boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
          overflow: 'hidden'
        }}>
          <div style={{ padding: '1.5rem', borderBottom: '1px solid #e5e7eb' }}>
            <h3 style={{ margin: 0, fontSize: '1.25rem', fontWeight: '600' }}>
              Historial de Reportes
            </h3>
          </div>
          
          {reports.length > 0 ? (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead style={{ backgroundColor: '#f9fafb' }}>
                  <tr>
                    <th style={{ padding: '1rem', textAlign: 'left', fontSize: '0.875rem', fontWeight: '500' }}>
                      Tipo
                    </th>
                    <th style={{ padding: '1rem', textAlign: 'left', fontSize: '0.875rem', fontWeight: '500' }}>
                      Cliente
                    </th>
                    <th style={{ padding: '1rem', textAlign: 'left', fontSize: '0.875rem', fontWeight: '500' }}>
                      Formato
                    </th>
                    <th style={{ padding: '1rem', textAlign: 'center', fontSize: '0.875rem', fontWeight: '500' }}>
                      Estado
                    </th>
                    <th style={{ padding: '1rem', textAlign: 'left', fontSize: '0.875rem', fontWeight: '500' }}>
                      Fecha Creación
                    </th>
                    <th style={{ padding: '1rem', textAlign: 'left', fontSize: '0.875rem', fontWeight: '500' }}>
                      Tamaño
                    </th>
                    <th style={{ padding: '1rem', textAlign: 'center', fontSize: '0.875rem', fontWeight: '500' }}>
                      Acciones
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {reports.map((report) => (
                    <tr key={report.id} style={{ borderBottom: '1px solid #e5e7eb' }}>
                      <td style={{ padding: '1rem' }}>
                        <span style={{
                          padding: '0.25rem 0.5rem',
                          backgroundColor: '#e0e7ff',
                          color: '#3730a3',
                          borderRadius: '0.25rem',
                          fontSize: '0.75rem'
                        }}>
                          {report.report_type?.replace('_', ' ') || 'N/A'}
                        </span>
                      </td>
                      <td style={{ padding: '1rem', fontSize: '0.875rem' }}>
                        {report.client?.name || 'Todos'}
                      </td>
                      <td style={{ padding: '1rem' }}>
                        <span style={{
                          padding: '0.25rem 0.5rem',
                          backgroundColor: '#f3f4f6',
                          color: '#6b7280',
                          borderRadius: '0.25rem',
                          fontSize: '0.75rem'
                        }}>
                          {report.format}
                        </span>
                      </td>
                      <td style={{ padding: '1rem', textAlign: 'center' }}>
                        <span style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          padding: '0.25rem 0.5rem',
                          backgroundColor: `${getStatusColor(report.status)}20`,
                          color: getStatusColor(report.status),
                          borderRadius: '0.25rem',
                          fontSize: '0.75rem',
                          fontWeight: '500'
                        }}>
                          {getStatusIcon(report.status)} {report.status}
                        </span>
                      </td>
                      <td style={{ padding: '1rem', fontSize: '0.875rem', color: '#6b7280' }}>
                        {formatDate(report.created_at)}
                      </td>
                      <td style={{ padding: '1rem', fontSize: '0.875rem', color: '#6b7280' }}>
                        {formatFileSize(report.file_size)}
                      </td>
                      <td style={{ padding: '1rem', textAlign: 'center' }}>
                        <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'center' }}>
                          {report.status === 'COMPLETED' && (
                            <button
                              onClick={() => handleDownload(report.id, `reporte_${report.id}.${report.format.toLowerCase()}`)}
                              style={{
                                padding: '0.25rem 0.5rem',
                                backgroundColor: '#059669',
                                color: 'white',
                                border: 'none',
                                borderRadius: '0.25rem',
                                cursor: 'pointer',
                                fontSize: '0.75rem'
                              }}
                              title="Descargar"
                            >
                              ⬇️
                            </button>
                          )}
                          
                          {(report.status === 'PENDING' || report.status === 'PROCESSING') && (
                            <button
                              onClick={() => refreshReportStatus(report.id)}
                              style={{
                                padding: '0.25rem 0.5rem',
                                backgroundColor: '#f3f4f6',
                                border: '1px solid #d1d5db',
                                borderRadius: '0.25rem',
                                cursor: 'pointer',
                                fontSize: '0.75rem'
                              }}
                              title="Actualizar estado"
                            >
                              🔄
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div style={{
              textAlign: 'center',
              padding: '3rem',
              color: '#6b7280'
            }}>
              <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>📄</div>
              <h3 style={{ margin: '0 0 0.5rem 0' }}>No hay reportes generados</h3>
              <p style={{ margin: 0 }}>
                Genera tu primer reporte de certificados
              </p>
            </div>
          )}
        </div>

        {/* Modal para generar reporte */}
        {showGenerateModal && (
          <div style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: 'rgba(0,0,0,0.5)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000
          }}>
            <div style={{
              backgroundColor: 'white',
              padding: '2rem',
              borderRadius: '0.5rem',
              width: '100%',
              maxWidth: '500px',
              maxHeight: '90vh',
              overflowY: 'auto'
            }}>
              <h3 style={{ margin: '0 0 1.5rem 0', fontSize: '1.5rem', fontWeight: '600' }}>
                Generar Nuevo Reporte
              </h3>
              
              <form onSubmit={handleGenerateReport}>
                {/* Cliente */}
                <div style={{ marginBottom: '1rem' }}>
                  <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500' }}>
                    Cliente
                  </label>
                  <select
                    value={formData.client_id}
                    onChange={(e) => setFormData({...formData, client_id: e.target.value})}
                    style={{
                      width: '100%',
                      padding: '0.75rem',
                      border: '1px solid #d1d5db',
                      borderRadius: '0.375rem'
                    }}
                  >
                    <option value="">Todos los clientes</option>
                    {clients.map(client => (
                      <option key={client.id} value={client.id}>
                        {client.name}
                      </option>
                    ))}
                  </select>
                </div>

                {/* Tipo de reporte */}
                <div style={{ marginBottom: '1rem' }}>
                  <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500' }}>
                    Tipo de Reporte
                  </label>
                  <select
                    value={formData.report_type}
                    onChange={(e) => setFormData({...formData, report_type: e.target.value})}
                    style={{
                      width: '100%',
                      padding: '0.75rem',
                      border: '1px solid #d1d5db',
                      borderRadius: '0.375rem'
                    }}
                  >
                    <option value="CERTIFICATE_SUMMARY">Resumen de Certificados</option>
                    <option value="CERTIFICATE_DETAILED">Reporte Detallado</option>
                    <option value="VULNERABILITY_SUMMARY">Resumen de Vulnerabilidades</option>
                    <option value="CLIENT_OVERVIEW">Vista General de Cliente</option>
                  </select>
                </div>

                {/* Formato */}
                <div style={{ marginBottom: '1rem' }}>
                  <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500' }}>
                    Formato
                  </label>
                  <select
                    value={formData.format}
                    onChange={(e) => setFormData({...formData, format: e.target.value})}
                    style={{
                      width: '100%',
                      padding: '0.75rem',
                      border: '1px solid #d1d5db',
                      borderRadius: '0.375rem'
                    }}
                  >
                    <option value="PDF">PDF</option>
                    <option value="EXCEL">Excel</option>
                    <option value="JSON">JSON</option>
                  </select>
                </div>

                {/* Filtros adicionales */}
                <div style={{ marginBottom: '1rem' }}>
                  <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500' }}>
                    Protocolo (opcional)
                  </label>
                  <select
                    value={formData.filters.protocol}
                    onChange={(e) => setFormData({
                      ...formData, 
                      filters: {...formData.filters, protocol: e.target.value}
                    })}
                    style={{
                      width: '100%',
                      padding: '0.75rem',
                      border: '1px solid #d1d5db',
                      borderRadius: '0.375rem'
                    }}
                  >
                    <option value="">Todos los protocolos</option>
                    <option value="HTTPS">HTTPS</option>
                    <option value="TLS">TLS</option>
                    <option value="SSH">SSH</option>
                    <option value="SMTP">SMTP</option>
                  </select>
                </div>

                <div style={{ marginBottom: '1.5rem' }}>
                  <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500' }}>
                    Expiran en (días, opcional)
                  </label>
                  <input
                    type="number"
                    value={formData.filters.expires_within_days}
                    onChange={(e) => setFormData({
                      ...formData, 
                      filters: {...formData.filters, expires_within_days: e.target.value}
                    })}
                    placeholder="ej: 30"
                    style={{
                      width: '100%',
                      padding: '0.75rem',
                      border: '1px solid #d1d5db',
                      borderRadius: '0.375rem'
                    }}
                  />
                </div>

                {/* Botones */}
                <div style={{ display: 'flex', gap: '1rem', justifyContent: 'flex-end' }}>
                  <button
                    type="button"
                    onClick={() => setShowGenerateModal(false)}
                    style={{
                      padding: '0.75rem 1.5rem',
                      backgroundColor: 'transparent',
                      color: '#6b7280',
                      border: '1px solid #d1d5db',
                      borderRadius: '0.375rem',
                      cursor: 'pointer'
                    }}
                  >
                    Cancelar
                  </button>
                  <button
                    type="submit"
                    disabled={generating}
                    style={{
                      padding: '0.75rem 1.5rem',
                      backgroundColor: generating ? '#9ca3af' : '#4f46e5',
                      color: 'white',
                      border: 'none',
                      borderRadius: '0.375rem',
                      cursor: generating ? 'not-allowed' : 'pointer',
                      fontWeight: '500'
                    }}
                  >
                    {generating ? 'Generando...' : 'Generar Reporte'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
};

export default Reports;