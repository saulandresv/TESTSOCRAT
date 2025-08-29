import React, { useState, useEffect } from 'react';
import Layout from './Layout';
import { AnalysisService } from '../services/analysis';

const Analysis = () => {
  const [analyses, setAnalyses] = useState([]);
  const [selectedAnalysis, setSelectedAnalysis] = useState(null);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [filters, setFilters] = useState({
    type: '',
    success: '',
    date_from: '',
    date_to: ''
  });

  useEffect(() => {
    loadAnalyses();
  }, [filters]);

  const loadAnalyses = async () => {
    try {
      setLoading(true);
      const params = {};
      if (filters.type) params.tipo = filters.type;
      if (filters.success) params.success = filters.success;
      if (filters.date_from) params.date_from = filters.date_from;
      if (filters.date_to) params.date_to = filters.date_to;

      const response = await AnalysisService.getAnalyses(params);
      setAnalyses(response.results || response);
    } catch (error) {
      console.error('Error loading analyses:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadAnalysisDetail = async (analysisId) => {
    try {
      setDetailLoading(true);
      const response = await AnalysisService.getAnalysis(analysisId);
      setSelectedAnalysis(response);
    } catch (error) {
      console.error('Error loading analysis detail:', error);
    } finally {
      setDetailLoading(false);
    }
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleString('es-CL');
  };

  const getSeverityColor = (severity) => {
    const colors = {
      'CRITICAL': '#dc2626',
      'HIGH': '#f59e0b',
      'MEDIUM': '#fbbf24',
      'LOW': '#10b981'
    };
    return colors[severity] || '#6b7280';
  };

  const getScoreColor = (score) => {
    if (score >= 90) return '#059669';
    if (score >= 80) return '#10b981';
    if (score >= 70) return '#fbbf24';
    if (score >= 60) return '#f59e0b';
    return '#dc2626';
  };

  const getScoreGrade = (score) => {
    if (score >= 90) return 'A';
    if (score >= 80) return 'B';
    if (score >= 70) return 'C';
    if (score >= 60) return 'D';
    return 'F';
  };

  const SecurityScoreVisualization = ({ score, vulnerabilities = [] }) => {
    const radius = 50;
    const strokeWidth = 8;
    const circumference = 2 * Math.PI * radius;
    const strokeDasharray = circumference;
    const strokeDashoffset = circumference - (score / 100) * circumference;
    
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
        <div style={{ position: 'relative', width: '120px', height: '120px' }}>
          <svg width="120" height="120" style={{ transform: 'rotate(-90deg)' }}>
            {/* Background circle */}
            <circle
              cx="60"
              cy="60"
              r={radius}
              fill="none"
              stroke="#e5e7eb"
              strokeWidth={strokeWidth}
            />
            {/* Progress circle */}
            <circle
              cx="60"
              cy="60"
              r={radius}
              fill="none"
              stroke={getScoreColor(score)}
              strokeWidth={strokeWidth}
              strokeLinecap="round"
              strokeDasharray={strokeDasharray}
              strokeDashoffset={strokeDashoffset}
              style={{ transition: 'stroke-dashoffset 1s ease-in-out' }}
            />
          </svg>
          {/* Score text */}
          <div style={{
            position: 'absolute',
            top: '50%',
            left: '50%',
            transform: 'translate(-50%, -50%)',
            textAlign: 'center'
          }}>
            <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: getScoreColor(score) }}>
              {score || 0}
            </div>
            <div style={{ fontSize: '0.75rem', color: '#6b7280' }}>
              Grade {getScoreGrade(score || 0)}
            </div>
          </div>
        </div>
        
        <div style={{ flex: 1 }}>
          <h4 style={{ margin: '0 0 0.5rem 0', color: '#1f2937' }}>Puntuación de Seguridad</h4>
          <div style={{ fontSize: '0.875rem', color: '#6b7280', marginBottom: '0.5rem' }}>
            {score >= 90 ? 'Excelente seguridad' :
             score >= 80 ? 'Buena seguridad' :
             score >= 70 ? 'Seguridad aceptable' :
             score >= 60 ? 'Seguridad deficiente' : 'Seguridad crítica'}
          </div>
          <div style={{ display: 'flex', gap: '0.25rem' }}>
            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(severity => {
              const count = vulnerabilities.filter(v => v.severity === severity).length;
              return count > 0 && (
                <span key={severity} style={{
                  padding: '0.125rem 0.375rem',
                  backgroundColor: `${getSeverityColor(severity)}20`,
                  color: getSeverityColor(severity),
                  borderRadius: '0.25rem',
                  fontSize: '0.625rem',
                  fontWeight: '500'
                }}>
                  {count} {severity.toLowerCase()}
                </span>
              );
            })}
          </div>
        </div>
      </div>
    );
  };

  const SeverityBadge = ({ severity, count }) => (
    <span style={{
      display: 'inline-flex',
      alignItems: 'center',
      padding: '0.25rem 0.5rem',
      backgroundColor: `${getSeverityColor(severity)}20`,
      color: getSeverityColor(severity),
      borderRadius: '0.375rem',
      fontSize: '0.75rem',
      fontWeight: '500',
      marginRight: '0.5rem'
    }}>
      {severity} ({count})
    </span>
  );

  const ProtocolMatrix = ({ protocols }) => {
    const protocolData = [
      { name: 'TLS 1.3', key: 'tls1_3', secure: true, recommended: true },
      { name: 'TLS 1.2', key: 'tls1_2', secure: true, recommended: true },
      { name: 'TLS 1.1', key: 'tls1_1', secure: false, recommended: false },
      { name: 'TLS 1.0', key: 'tls1_0', secure: false, recommended: false },
      { name: 'SSL 3.0', key: 'ssl3_0', secure: false, recommended: false },
      { name: 'SSL 2.0', key: 'ssl2_0', secure: false, recommended: false }
    ];

    return (
      <div style={{
        backgroundColor: '#f9fafb',
        padding: '1rem',
        borderRadius: '0.5rem',
        border: '1px solid #e5e7eb'
      }}>
        <h4 style={{ margin: '0 0 1rem 0', fontSize: '1rem', fontWeight: '600' }}>Soporte de Protocolos</h4>
        <div style={{ display: 'grid', gap: '0.5rem' }}>
          {protocolData.map(protocol => {
            const isSupported = protocols?.[protocol.key] || false;
            return (
              <div key={protocol.key} style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '0.5rem',
                backgroundColor: isSupported && !protocol.secure ? '#fef2f2' : 
                                isSupported && protocol.secure ? '#f0fdf4' : '#f9fafb',
                border: '1px solid',
                borderColor: isSupported && !protocol.secure ? '#fecaca' : 
                           isSupported && protocol.secure ? '#bbf7d0' : '#e5e7eb',
                borderRadius: '0.375rem',
                fontSize: '0.875rem'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span style={{
                    display: 'inline-block',
                    width: '8px',
                    height: '8px',
                    borderRadius: '50%',
                    backgroundColor: isSupported ? 
                      (protocol.secure ? '#10b981' : '#dc2626') : '#d1d5db'
                  }} />
                  <span style={{ fontWeight: '500' }}>{protocol.name}</span>
                  {protocol.recommended && (
                    <span style={{
                      padding: '0.125rem 0.25rem',
                      backgroundColor: '#dbeafe',
                      color: '#1e40af',
                      borderRadius: '0.25rem',
                      fontSize: '0.625rem',
                      fontWeight: '500'
                    }}>REC</span>
                  )}
                </div>
                <span style={{
                  color: isSupported ? (protocol.secure ? '#059669' : '#dc2626') : '#9ca3af',
                  fontWeight: '500'
                }}>
                  {isSupported ? '✓ Soportado' : '✗ No soportado'}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    );
  };

  const VulnerabilityDetail = ({ vulnerability }) => (
    <div style={{
      backgroundColor: `${getSeverityColor(vulnerability.severity)}10`,
      border: `1px solid ${getSeverityColor(vulnerability.severity)}30`,
      borderRadius: '0.5rem',
      padding: '1rem',
      marginBottom: '1rem'
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
        <h4 style={{ margin: 0, color: '#1f2937' }}>{vulnerability.vulnerabilidad}</h4>
        <SeverityBadge severity={vulnerability.severity} count={1} />
      </div>
      {vulnerability.description && (
        <p style={{ margin: 0, color: '#6b7280', fontSize: '0.875rem' }}>
          {vulnerability.description}
        </p>
      )}
      {vulnerability.recommendation && (
        <div style={{
          marginTop: '0.5rem',
          padding: '0.5rem',
          backgroundColor: '#f0f9ff',
          border: '1px solid #bae6fd',
          borderRadius: '0.375rem'
        }}>
          <div style={{ fontSize: '0.75rem', fontWeight: '500', color: '#0c4a6e', marginBottom: '0.25rem' }}>
            💡 Recomendación:
          </div>
          <div style={{ fontSize: '0.75rem', color: '#0c4a6e' }}>
            {vulnerability.recommendation}
          </div>
        </div>
      )}
    </div>
  );

  if (loading) {
    return (
      <Layout>
        <div style={{ textAlign: 'center', padding: '2rem' }}>
          <div style={{ fontSize: '1.5rem' }}>🔄</div>
          <p>Cargando análisis...</p>
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div style={{ maxWidth: '1400px', margin: '0 auto' }}>
        {/* Header */}
        <div style={{ marginBottom: '2rem' }}>
          <h2 style={{ fontSize: '1.875rem', fontWeight: 'bold', color: '#1f2937', margin: 0 }}>
            🔍 Análisis SSL/TLS
          </h2>
          <p style={{ color: '#6b7280', margin: '0.5rem 0 0 0' }}>
            Historial y resultados de análisis de certificados
          </p>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem' }}>
          {/* Lista de análisis */}
          <div>
            {/* Filtros */}
            <div style={{
              backgroundColor: 'white',
              padding: '1.5rem',
              borderRadius: '0.5rem',
              boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
              marginBottom: '1.5rem'
            }}>
              <h3 style={{ margin: '0 0 1rem 0', fontSize: '1.125rem', fontWeight: '600' }}>
                Filtros
              </h3>
              <div style={{
                display: 'grid',
                gridTemplateColumns: '1fr 1fr',
                gap: '1rem',
                marginBottom: '1rem'
              }}>
                <select
                  value={filters.type}
                  onChange={(e) => setFilters({...filters, type: e.target.value})}
                  style={{
                    padding: '0.5rem',
                    border: '1px solid #d1d5db',
                    borderRadius: '0.375rem'
                  }}
                >
                  <option value="">Todos los tipos</option>
                  <option value="SSL_TLS">SSL/TLS</option>
                  <option value="SSH">SSH</option>
                  <option value="WEB">Web Security</option>
                  <option value="FULL">Análisis Completo</option>
                </select>

                <select
                  value={filters.success}
                  onChange={(e) => setFilters({...filters, success: e.target.value})}
                  style={{
                    padding: '0.5rem',
                    border: '1px solid #d1d5db',
                    borderRadius: '0.375rem'
                  }}
                >
                  <option value="">Todos los estados</option>
                  <option value="true">Exitosos</option>
                  <option value="false">Fallidos</option>
                </select>
              </div>
              
              <div style={{
                display: 'grid',
                gridTemplateColumns: '1fr 1fr',
                gap: '1rem'
              }}>
                <input
                  type="date"
                  value={filters.date_from}
                  onChange={(e) => setFilters({...filters, date_from: e.target.value})}
                  style={{
                    padding: '0.5rem',
                    border: '1px solid #d1d5db',
                    borderRadius: '0.375rem'
                  }}
                  placeholder="Fecha desde"
                />
                
                <input
                  type="date"
                  value={filters.date_to}
                  onChange={(e) => setFilters({...filters, date_to: e.target.value})}
                  style={{
                    padding: '0.5rem',
                    border: '1px solid #d1d5db',
                    borderRadius: '0.375rem'
                  }}
                  placeholder="Fecha hasta"
                />
              </div>
            </div>

            {/* Lista de análisis */}
            <div style={{
              backgroundColor: 'white',
              borderRadius: '0.5rem',
              boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
              maxHeight: '600px',
              overflowY: 'auto'
            }}>
              <div style={{ padding: '1rem', borderBottom: '1px solid #e5e7eb' }}>
                <h3 style={{ margin: 0, fontSize: '1.125rem', fontWeight: '600' }}>
                  Análisis Recientes ({analyses.length})
                </h3>
              </div>
              
              {analyses.length > 0 ? (
                <div>
                  {analyses.map((analysis) => (
                    <div
                      key={analysis.id}
                      onClick={() => loadAnalysisDetail(analysis.id)}
                      style={{
                        padding: '1rem',
                        borderBottom: '1px solid #e5e7eb',
                        cursor: 'pointer',
                        backgroundColor: selectedAnalysis?.id === analysis.id ? '#f0f9ff' : 'white',
                        transition: 'background-color 0.2s'
                      }}
                      onMouseEnter={(e) => {
                        if (selectedAnalysis?.id !== analysis.id) {
                          e.target.style.backgroundColor = '#f9fafb';
                        }
                      }}
                      onMouseLeave={(e) => {
                        if (selectedAnalysis?.id !== analysis.id) {
                          e.target.style.backgroundColor = 'white';
                        }
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center' }}>
                          <span style={{
                            padding: '0.25rem 0.5rem',
                            backgroundColor: analysis.tuvo_exito ? '#dcfce7' : '#fef2f2',
                            color: analysis.tuvo_exito ? '#16a34a' : '#dc2626',
                            borderRadius: '0.25rem',
                            fontSize: '0.75rem',
                            fontWeight: '500',
                            marginRight: '0.5rem'
                          }}>
                            {analysis.tuvo_exito ? '✅' : '❌'}
                          </span>
                          <span style={{ fontWeight: '500' }}>
                            {analysis.certificado_info}
                          </span>
                        </div>
                        <span style={{
                          padding: '0.25rem 0.5rem',
                          backgroundColor: '#f3f4f6',
                          color: '#6b7280',
                          borderRadius: '0.25rem',
                          fontSize: '0.75rem'
                        }}>
                          {analysis.tipo}
                        </span>
                      </div>
                      
                      <div style={{ fontSize: '0.875rem', color: '#6b7280', marginBottom: '0.5rem' }}>
                        {formatDate(analysis.fecha_inicio)}
                      </div>
                      
                      {analysis.vulnerabilities_summary && (
                        <div style={{ display: 'flex', alignItems: 'center' }}>
                          <span style={{ fontSize: '0.75rem', color: '#6b7280', marginRight: '0.5rem' }}>
                            Vulnerabilidades:
                          </span>
                          <span style={{
                            padding: '0.25rem 0.5rem',
                            backgroundColor: analysis.vulnerabilities_summary.critical_high > 0 ? '#fef2f2' : '#f0f9ff',
                            color: analysis.vulnerabilities_summary.critical_high > 0 ? '#dc2626' : '#3b82f6',
                            borderRadius: '0.25rem',
                            fontSize: '0.75rem'
                          }}>
                            {analysis.vulnerabilities_summary.total} total
                            {analysis.vulnerabilities_summary.critical_high > 0 && 
                              ` (${analysis.vulnerabilities_summary.critical_high} críticas/altas)`
                            }
                          </span>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <div style={{
                  textAlign: 'center',
                  padding: '2rem',
                  color: '#6b7280'
                }}>
                  <div style={{ fontSize: '2rem', marginBottom: '1rem' }}>🔍</div>
                  <p>No hay análisis disponibles</p>
                </div>
              )}
            </div>
          </div>

          {/* Detalle del análisis */}
          <div>
            {selectedAnalysis ? (
              <div style={{
                backgroundColor: 'white',
                borderRadius: '0.5rem',
                boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
                maxHeight: '800px',
                overflowY: 'auto'
              }}>
                {detailLoading ? (
                  <div style={{ textAlign: 'center', padding: '2rem' }}>
                    <div style={{ fontSize: '1.5rem' }}>🔄</div>
                    <p>Cargando detalle...</p>
                  </div>
                ) : (
                  <div>
                    {/* Header del detalle */}
                    <div style={{ padding: '1.5rem', borderBottom: '1px solid #e5e7eb' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                        <h3 style={{ margin: 0, fontSize: '1.25rem', fontWeight: '600' }}>
                          Detalle del Análisis
                        </h3>
                        <span style={{
                          padding: '0.5rem 1rem',
                          backgroundColor: selectedAnalysis.tuvo_exito ? '#dcfce7' : '#fef2f2',
                          color: selectedAnalysis.tuvo_exito ? '#16a34a' : '#dc2626',
                          borderRadius: '0.5rem',
                          fontSize: '0.875rem',
                          fontWeight: '500'
                        }}>
                          {selectedAnalysis.tuvo_exito ? '✅ Exitoso' : '❌ Fallido'}
                        </span>
                      </div>
                      
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', fontSize: '0.875rem' }}>
                        <div>
                          <strong>Certificado:</strong> {selectedAnalysis.certificado_info?.target}:{selectedAnalysis.certificado_info?.puerto}
                        </div>
                        <div>
                          <strong>Tipo:</strong> {selectedAnalysis.tipo}
                        </div>
                        <div>
                          <strong>Inicio:</strong> {formatDate(selectedAnalysis.fecha_inicio)}
                        </div>
                        <div>
                          <strong>Duración:</strong> {selectedAnalysis.duration_seconds ? `${selectedAnalysis.duration_seconds}s` : 'N/A'}
                        </div>
                      </div>
                    </div>

                    <div style={{ padding: '1.5rem' }}>
                      {/* Security Score Visualization */}
                      {selectedAnalysis.puntuacion_seguridad && (
                        <div style={{ marginBottom: '2rem' }}>
                          <SecurityScoreVisualization 
                            score={selectedAnalysis.puntuacion_seguridad} 
                            vulnerabilities={selectedAnalysis.vulnerabilidades || []}
                          />
                        </div>
                      )}

                      {/* Protocol Matrix */}
                      {selectedAnalysis.parametros_tls && (
                        <div style={{ marginBottom: '2rem' }}>
                          <ProtocolMatrix protocols={selectedAnalysis.parametros_tls} />
                        </div>
                      )}
                      
                      {/* Vulnerabilidades */}
                      {selectedAnalysis.vulnerabilidades && selectedAnalysis.vulnerabilidades.length > 0 && (
                        <div style={{ marginBottom: '2rem' }}>
                          <h4 style={{ margin: '0 0 1rem 0', fontSize: '1.125rem', fontWeight: '600' }}>
                            🚨 Vulnerabilidades Detectadas ({selectedAnalysis.vulnerabilities_count?.total || 0})
                          </h4>
                          
                          {/* Resumen por severidad */}
                          <div style={{ marginBottom: '1rem' }}>
                            {selectedAnalysis.vulnerabilities_count?.critical > 0 && 
                              <SeverityBadge severity="CRITICAL" count={selectedAnalysis.vulnerabilities_count.critical} />}
                            {selectedAnalysis.vulnerabilities_count?.high > 0 && 
                              <SeverityBadge severity="HIGH" count={selectedAnalysis.vulnerabilities_count.high} />}
                            {selectedAnalysis.vulnerabilities_count?.medium > 0 && 
                              <SeverityBadge severity="MEDIUM" count={selectedAnalysis.vulnerabilities_count.medium} />}
                            {selectedAnalysis.vulnerabilities_count?.low > 0 && 
                              <SeverityBadge severity="LOW" count={selectedAnalysis.vulnerabilities_count.low} />}
                          </div>

                          {/* Lista de vulnerabilidades */}
                          {selectedAnalysis.vulnerabilidades.map((vuln, index) => (
                            <VulnerabilityDetail key={vuln.id || index} vulnerability={vuln} />
                          ))}
                        </div>
                      )}

                      {/* Parámetros generales */}
                      {selectedAnalysis.parametros_generales && (
                        <div style={{ marginBottom: '2rem' }}>
                          <h4 style={{ margin: '0 0 1rem 0', fontSize: '1.125rem', fontWeight: '600' }}>
                            📋 Información del Certificado
                          </h4>
                          <div style={{
                            backgroundColor: '#f9fafb',
                            padding: '1rem',
                            borderRadius: '0.5rem',
                            fontSize: '0.875rem'
                          }}>
                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
                              <div><strong>CN:</strong> {selectedAnalysis.parametros_generales.common_name || 'N/A'}</div>
                              <div><strong>Emisor:</strong> {selectedAnalysis.parametros_generales.issuer || 'N/A'}</div>
                              <div><strong>Válido desde:</strong> {selectedAnalysis.parametros_generales.fecha_inicio || 'N/A'}</div>
                              <div><strong>Válido hasta:</strong> {selectedAnalysis.parametros_generales.fecha_fin || 'N/A'}</div>
                              <div><strong>Días restantes:</strong> 
                                <span style={{
                                  color: selectedAnalysis.parametros_generales.dias_restantes < 30 ? '#dc2626' : '#059669',
                                  fontWeight: '500',
                                  marginLeft: '0.5rem'
                                }}>
                                  {selectedAnalysis.parametros_generales.dias_restantes || 'N/A'}
                                </span>
                              </div>
                              <div><strong>Algoritmo:</strong> {selectedAnalysis.parametros_generales.algoritmo_firma || 'N/A'}</div>
                            </div>
                          </div>
                        </div>
                      )}

                      {/* Cipher Suites Analysis */}
                      {selectedAnalysis.cipher_analysis && (
                        <div style={{ marginBottom: '2rem' }}>
                          <h4 style={{ margin: '0 0 1rem 0', fontSize: '1.125rem', fontWeight: '600' }}>
                            🔐 Análisis de Cifrados
                          </h4>
                          <div style={{
                            backgroundColor: '#f9fafb',
                            padding: '1rem',
                            borderRadius: '0.5rem',
                            border: '1px solid #e5e7eb'
                          }}>
                            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
                              <div style={{ textAlign: 'center' }}>
                                <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#059669' }}>
                                  {selectedAnalysis.cipher_analysis.strong_ciphers || 0}
                                </div>
                                <div style={{ fontSize: '0.75rem', color: '#6b7280' }}>Cifrados Fuertes</div>
                              </div>
                              <div style={{ textAlign: 'center' }}>
                                <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#f59e0b' }}>
                                  {selectedAnalysis.cipher_analysis.weak_ciphers || 0}
                                </div>
                                <div style={{ fontSize: '0.75rem', color: '#6b7280' }}>Cifrados Débiles</div>
                              </div>
                              <div style={{ textAlign: 'center' }}>
                                <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: selectedAnalysis.cipher_analysis.pfs_support ? '#059669' : '#dc2626' }}>
                                  {selectedAnalysis.cipher_analysis.pfs_support ? '✓' : '✗'}
                                </div>
                                <div style={{ fontSize: '0.75rem', color: '#6b7280' }}>Perfect Forward Secrecy</div>
                              </div>
                            </div>
                          </div>
                        </div>
                      )}

                      {/* Parámetros TLS */}
                      {selectedAnalysis.parametros_tls && (
                        <div style={{ marginBottom: '2rem' }}>
                          <h4 style={{ margin: '0 0 1rem 0', fontSize: '1.125rem', fontWeight: '600' }}>
                            🔐 Configuración TLS/SSL Detallada
                          </h4>
                          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                            <div style={{
                              backgroundColor: '#f9fafb',
                              padding: '1rem',
                              borderRadius: '0.5rem',
                              fontSize: '0.875rem',
                              border: '1px solid #e5e7eb'
                            }}>
                              <h5 style={{ margin: '0 0 0.5rem 0', color: '#1f2937' }}>Características de Seguridad</h5>
                              <div style={{ display: 'grid', gap: '0.5rem' }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                  <span>Perfect Forward Secrecy:</span>
                                  <span style={{ color: selectedAnalysis.parametros_tls.pfs ? '#059669' : '#dc2626', fontWeight: '500' }}>
                                    {selectedAnalysis.parametros_tls.pfs ? '✅ Sí' : '❌ No'}
                                  </span>
                                </div>
                                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                  <span>HSTS:</span>
                                  <span style={{ color: selectedAnalysis.parametros_tls.hsts ? '#059669' : '#f59e0b', fontWeight: '500' }}>
                                    {selectedAnalysis.parametros_tls.hsts ? '✅ Habilitado' : '⚠️ Deshabilitado'}
                                  </span>
                                </div>
                                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                  <span>OCSP Stapling:</span>
                                  <span style={{ color: selectedAnalysis.parametros_tls.ocsp_stapling ? '#059669' : '#f59e0b', fontWeight: '500' }}>
                                    {selectedAnalysis.parametros_tls.ocsp_stapling ? '✅ Sí' : '⚠️ No'}
                                  </span>
                                </div>
                              </div>
                            </div>
                            
                            <div style={{
                              backgroundColor: '#f9fafb',
                              padding: '1rem',
                              borderRadius: '0.5rem',
                              fontSize: '0.875rem',
                              border: '1px solid #e5e7eb'
                            }}>
                              <h5 style={{ margin: '0 0 0.5rem 0', color: '#1f2937' }}>Vulnerabilidades Comunes</h5>
                              <div style={{ display: 'grid', gap: '0.5rem' }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                  <span>Heartbleed:</span>
                                  <span style={{ color: selectedAnalysis.parametros_tls.heartbleed_vulnerable ? '#dc2626' : '#059669', fontWeight: '500' }}>
                                    {selectedAnalysis.parametros_tls.heartbleed_vulnerable ? '❌ Vulnerable' : '✅ Seguro'}
                                  </span>
                                </div>
                                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                  <span>POODLE (SSLv3):</span>
                                  <span style={{ color: selectedAnalysis.parametros_tls.sslv3_supported ? '#dc2626' : '#059669', fontWeight: '500' }}>
                                    {selectedAnalysis.parametros_tls.sslv3_supported ? '❌ Vulnerable' : '✅ Seguro'}
                                  </span>
                                </div>
                                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                  <span>RC4 Cipher:</span>
                                  <span style={{ color: selectedAnalysis.parametros_tls.rc4_supported ? '#dc2626' : '#059669', fontWeight: '500' }}>
                                    {selectedAnalysis.parametros_tls.rc4_supported ? '❌ Soportado' : '✅ No soportado'}
                                  </span>
                                </div>
                              </div>
                            </div>
                          </div>
                        </div>
                      )}

                      {/* Cadena de certificación */}
                      {selectedAnalysis.cadena_certificacion && (
                        <div style={{ marginBottom: '2rem' }}>
                          <h4 style={{ margin: '0 0 1rem 0', fontSize: '1.125rem', fontWeight: '600' }}>
                            🔗 Cadena de Certificación
                          </h4>
                          <div style={{
                            backgroundColor: '#f9fafb',
                            padding: '1rem',
                            borderRadius: '0.5rem',
                            fontSize: '0.875rem'
                          }}>
                            <div><strong>Estado de la cadena:</strong> 
                              <span style={{ 
                                color: selectedAnalysis.cadena_certificacion.cadena_ok ? '#059669' : '#dc2626', 
                                marginLeft: '0.5rem',
                                fontWeight: '500'
                              }}>
                                {selectedAnalysis.cadena_certificacion.cadena_ok ? '✅ Válida' : '❌ Inválida'}
                              </span>
                            </div>
                            <div><strong>Errores:</strong> 
                              <span style={{ 
                                color: selectedAnalysis.cadena_certificacion.errores ? '#dc2626' : '#059669', 
                                marginLeft: '0.5rem' 
                              }}>
                                {selectedAnalysis.cadena_certificacion.errores ? '❌ Sí' : '✅ No'}
                              </span>
                            </div>
                            <div><strong>Auto-firmado:</strong> 
                              <span style={{ 
                                color: selectedAnalysis.cadena_certificacion.autofirmado ? '#f59e0b' : '#059669', 
                                marginLeft: '0.5rem' 
                              }}>
                                {selectedAnalysis.cadena_certificacion.autofirmado ? '⚠️ Sí' : '✅ No'}
                              </span>
                            </div>
                          </div>
                        </div>
                      )}

                      {/* Error message si hay */}
                      {selectedAnalysis.error_message && (
                        <div style={{
                          backgroundColor: '#fef2f2',
                          border: '1px solid #fecaca',
                          padding: '1rem',
                          borderRadius: '0.5rem',
                          marginTop: '1rem'
                        }}>
                          <h4 style={{ margin: '0 0 0.5rem 0', color: '#dc2626' }}>Error</h4>
                          <p style={{ margin: 0, fontSize: '0.875rem', color: '#6b7280' }}>
                            {selectedAnalysis.error_message}
                          </p>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div style={{
                backgroundColor: 'white',
                borderRadius: '0.5rem',
                boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
                padding: '3rem',
                textAlign: 'center',
                color: '#6b7280'
              }}>
                <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>🔍</div>
                <h3 style={{ margin: '0 0 0.5rem 0' }}>Selecciona un análisis</h3>
                <p style={{ margin: 0 }}>
                  Haz clic en un análisis de la lista para ver los detalles
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </Layout>
  );
};

export default Analysis;