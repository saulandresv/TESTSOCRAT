import React, { useState, useEffect } from 'react';
import Layout from './Layout';
import { AnalysisService } from '../services/analysis';
import { CertificateService } from '../services/certificates';

const Dashboard = () => {
  const [stats, setStats] = useState(null);
  const [certificates, setCertificates] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    try {
      setLoading(true);
      const [statsResponse, certsResponse] = await Promise.all([
        AnalysisService.getDashboardStats(),
        CertificateService.getCertificates({ limit: 5, ordering: '-created_at' })
      ]);

      setStats(statsResponse);
      setCertificates(certsResponse.results || certsResponse);
    } catch (error) {
      console.error('Error loading dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const StatCard = ({ title, value, icon, color = '#4f46e5', trend = null, subtitle = null }) => (
    <div style={{
      backgroundColor: 'white',
      padding: '1.5rem',
      borderRadius: '0.5rem',
      boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
      border: `2px solid ${color}20`,
      position: 'relative',
      overflow: 'hidden'
    }}>
      {/* Gradient background accent */}
      <div style={{
        position: 'absolute',
        top: 0,
        right: 0,
        bottom: 0,
        width: '4px',
        background: `linear-gradient(180deg, ${color}, ${color}80)`
      }} />
      
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ flex: 1 }}>
          <p style={{ margin: 0, color: '#6b7280', fontSize: '0.875rem' }}>
            {title}
          </p>
          <p style={{ margin: '0.5rem 0 0 0', fontSize: '2rem', fontWeight: 'bold', color }}>
            {value}
          </p>
          {subtitle && (
            <p style={{ margin: '0.25rem 0 0 0', color: '#9ca3af', fontSize: '0.75rem' }}>
              {subtitle}
            </p>
          )}
          {trend && (
            <div style={{ display: 'flex', alignItems: 'center', marginTop: '0.5rem' }}>
              <span style={{
                fontSize: '0.75rem',
                color: trend.direction === 'up' ? '#059669' : trend.direction === 'down' ? '#dc2626' : '#6b7280',
                display: 'flex',
                alignItems: 'center',
                gap: '0.25rem'
              }}>
                {trend.direction === 'up' ? '📈' : trend.direction === 'down' ? '📉' : '➡️'}
                {trend.value}% {trend.period}
              </span>
            </div>
          )}
        </div>
        <div style={{ fontSize: '2.5rem', opacity: 0.7, marginLeft: '1rem' }}>
          {icon}
        </div>
      </div>
    </div>
  );

  const VulnerabilityChart = ({ vulnerabilities }) => {
    const total = vulnerabilities?.total || 0;
    const data = [
      { name: 'Críticas', value: vulnerabilities?.critical || 0, color: '#dc2626' },
      { name: 'Altas', value: vulnerabilities?.high || 0, color: '#f59e0b' },
      { name: 'Medias', value: vulnerabilities?.medium || 0, color: '#fbbf24' },
      { name: 'Bajas', value: vulnerabilities?.low || 0, color: '#10b981' }
    ];

    return (
      <div>
        <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '1rem' }}>
          <div style={{ position: 'relative', width: '120px', height: '120px' }}>
            <svg width="120" height="120" style={{ transform: 'rotate(-90deg)' }}>
              {data.reduce((acc, item, index) => {
                const percentage = total > 0 ? (item.value / total) * 100 : 0;
                const strokeDasharray = `${percentage * 3.14} 314`;
                const strokeDashoffset = acc.offset;
                
                acc.elements.push(
                  <circle
                    key={item.name}
                    cx="60"
                    cy="60"
                    r="50"
                    fill="none"
                    stroke={item.color}
                    strokeWidth="8"
                    strokeDasharray={strokeDasharray}
                    strokeDashoffset={strokeDashoffset}
                    strokeLinecap="round"
                  />
                );
                
                acc.offset -= percentage * 3.14;
                return acc;
              }, { elements: [], offset: 0 }).elements}
            </svg>
            <div style={{
              position: 'absolute',
              top: '50%',
              left: '50%',
              transform: 'translate(-50%, -50%)',
              textAlign: 'center'
            }}>
              <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#1f2937' }}>
                {total}
              </div>
              <div style={{ fontSize: '0.75rem', color: '#6b7280' }}>
                Total
              </div>
            </div>
          </div>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
          {data.map(item => (
            <div key={item.name} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <div style={{
                width: '12px',
                height: '12px',
                borderRadius: '2px',
                backgroundColor: item.color
              }} />
              <span style={{ fontSize: '0.75rem', color: '#6b7280' }}>
                {item.name}: {item.value}
              </span>
            </div>
          ))}
        </div>
      </div>
    );
  };

  const AlertsPanel = ({ stats }) => {
    const alerts = [];
    
    if (stats?.recent_vulnerabilities?.critical > 0) {
      alerts.push({
        type: 'critical',
        message: `${stats.recent_vulnerabilities.critical} vulnerabilidades críticas requieren atención inmediata`,
        icon: '🚨',
        action: 'Ver Análisis'
      });
    }
    
    if (stats?.certificates_expiring_soon > 0) {
      alerts.push({
        type: 'warning',
        message: `${stats.certificates_expiring_soon} certificados expiran en menos de 30 días`,
        icon: '⏰',
        action: 'Ver Certificados'
      });
    }
    
    if (stats?.failed_last_24h > 5) {
      alerts.push({
        type: 'warning',
        message: `${stats.failed_last_24h} análisis fallidos en las últimas 24 horas`,
        icon: '⚠️',
        action: 'Investigar'
      });
    }
    
    if (alerts.length === 0) {
      alerts.push({
        type: 'success',
        message: 'Todos los sistemas funcionan correctamente',
        icon: '✅',
        action: null
      });
    }

    return (
      <div style={{
        backgroundColor: 'white',
        padding: '1.5rem',
        borderRadius: '0.5rem',
        boxShadow: '0 1px 3px rgba(0,0,0,0.1)'
      }}>
        <h3 style={{ margin: '0 0 1rem 0', fontSize: '1.25rem', fontWeight: '600' }}>
          🔔 Alertas y Notificaciones
        </h3>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          {alerts.map((alert, index) => {
            const bgColor = {
              critical: '#fef2f2',
              warning: '#fffbeb',
              success: '#f0fdf4'
            }[alert.type];
            
            const borderColor = {
              critical: '#fecaca',
              warning: '#fed7aa',
              success: '#bbf7d0'
            }[alert.type];
            
            const textColor = {
              critical: '#991b1b',
              warning: '#92400e',
              success: '#166534'
            }[alert.type];

            return (
              <div key={index} style={{
                backgroundColor: bgColor,
                border: `1px solid ${borderColor}`,
                borderRadius: '0.5rem',
                padding: '1rem',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                  <span style={{ fontSize: '1.25rem' }}>{alert.icon}</span>
                  <span style={{ fontSize: '0.875rem', color: textColor }}>
                    {alert.message}
                  </span>
                </div>
                {alert.action && (
                  <button style={{
                    padding: '0.25rem 0.75rem',
                    backgroundColor: 'transparent',
                    border: `1px solid ${textColor}`,
                    borderRadius: '0.25rem',
                    color: textColor,
                    fontSize: '0.75rem',
                    cursor: 'pointer'
                  }}>
                    {alert.action}
                  </button>
                )}
              </div>
            );
          })}
        </div>
      </div>
    );
  };

  if (loading) {
    return (
      <Layout>
        <div style={{ textAlign: 'center', padding: '2rem' }}>
          <div style={{ fontSize: '1.5rem' }}>🔄</div>
          <p>Cargando dashboard...</p>
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div style={{ maxWidth: '1200px', margin: '0 auto' }}>
        {/* Encabezado */}
        <div style={{ marginBottom: '2rem' }}>
          <h2 style={{ fontSize: '1.875rem', fontWeight: 'bold', color: '#1f2937', margin: 0 }}>
            Dashboard
          </h2>
          <p style={{ color: '#6b7280', margin: '0.5rem 0 0 0' }}>
            Vista general del sistema de monitoreo SSL/TLS
          </p>
        </div>

        {/* Alertas */}
        <div style={{ marginBottom: '2rem' }}>
          <AlertsPanel stats={stats} />
        </div>

        {/* Estadísticas principales */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
          gap: '1.5rem',
          marginBottom: '2rem'
        }}>
          <StatCard
            title="Certificados Monitoreados"
            value={stats?.total_certificates || 0}
            icon="🔒"
            color="#4f46e5"
            trend={{ direction: 'up', value: 12, period: 'este mes' }}
            subtitle={`${stats?.active_certificates || 0} activos`}
          />
          <StatCard
            title="Análisis Ejecutados"
            value={stats?.total_analyses || 0}
            icon="📊"
            color="#059669"
            trend={{ direction: 'up', value: 8, period: 'esta semana' }}
            subtitle={`${stats?.analyses_today || 0} hoy`}
          />
          <StatCard
            title="Vulnerabilidades Activas"
            value={stats?.total_vulnerabilities || 0}
            icon="🚨"
            color="#dc2626"
            trend={{ direction: 'down', value: 15, period: 'último mes' }}
            subtitle={`${stats?.recent_vulnerabilities?.critical || 0} críticas`}
          />
          <StatCard
            title="Puntuación Promedio"
            value={stats?.average_security_score ? `${stats.average_security_score}/100` : 'N/A'}
            icon="🏆"
            color="#f59e0b"
            trend={{ direction: 'up', value: 5, period: 'último análisis' }}
            subtitle={stats?.security_grade || 'Sin datos'}
          />
        </div>

        {/* Grid de tres columnas */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(350px, 1fr))',
          gap: '2rem',
          marginBottom: '2rem'
        }}>
          {/* Vulnerabilidades por severidad con gráfico */}
          <div style={{
            backgroundColor: 'white',
            padding: '1.5rem',
            borderRadius: '0.5rem',
            boxShadow: '0 1px 3px rgba(0,0,0,0.1)'
          }}>
            <h3 style={{ margin: '0 0 1.5rem 0', fontSize: '1.25rem', fontWeight: '600' }}>
              🛡️ Distribución de Vulnerabilidades
            </h3>
            {stats?.recent_vulnerabilities ? (
              <VulnerabilityChart vulnerabilities={stats.recent_vulnerabilities} />
            ) : (
              <div style={{ textAlign: 'center', color: '#6b7280', padding: '2rem' }}>
                <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>📊</div>
                <p>No hay datos de vulnerabilidades</p>
              </div>
            )}
          </div>

          {/* Estado de Certificados */}
          <div style={{
            backgroundColor: 'white',
            padding: '1.5rem',
            borderRadius: '0.5rem',
            boxShadow: '0 1px 3px rgba(0,0,0,0.1)'
          }}>
            <h3 style={{ margin: '0 0 1rem 0', fontSize: '1.25rem', fontWeight: '600' }}>
              📋 Estado de Certificados
            </h3>
            {stats ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                <div style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '0.75rem',
                  backgroundColor: '#f0fdf4',
                  borderRadius: '0.5rem',
                  border: '1px solid #bbf7d0'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span>🟢</span>
                    <span style={{ fontWeight: '500' }}>Activos</span>
                  </div>
                  <span style={{ color: '#059669', fontWeight: 'bold', fontSize: '1.25rem' }}>
                    {stats.active_certificates || 0}
                  </span>
                </div>
                
                <div style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '0.75rem',
                  backgroundColor: '#fef2f2',
                  borderRadius: '0.5rem',
                  border: '1px solid #fecaca'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span>🔴</span>
                    <span style={{ fontWeight: '500' }}>Inactivos</span>
                  </div>
                  <span style={{ color: '#dc2626', fontWeight: 'bold', fontSize: '1.25rem' }}>
                    {stats.inactive_certificates || 0}
                  </span>
                </div>
                
                <div style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '0.75rem',
                  backgroundColor: '#fffbeb',
                  borderRadius: '0.5rem',
                  border: '1px solid #fed7aa'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span>⏰</span>
                    <span style={{ fontWeight: '500' }}>Por expirar (30d)</span>
                  </div>
                  <span style={{ color: '#f59e0b', fontWeight: 'bold', fontSize: '1.25rem' }}>
                    {stats.certificates_expiring_soon || 0}
                  </span>
                </div>
                
                <div style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '0.75rem',
                  backgroundColor: '#f8fafc',
                  borderRadius: '0.5rem',
                  border: '1px solid #e2e8f0'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span>📊</span>
                    <span style={{ fontWeight: '500' }}>Puntuación promedio</span>
                  </div>
                  <span style={{ color: '#4f46e5', fontWeight: 'bold', fontSize: '1.25rem' }}>
                    {stats.average_security_score || 'N/A'}
                  </span>
                </div>
              </div>
            ) : (
              <p style={{ color: '#6b7280' }}>No hay datos de certificados</p>
            )}
          </div>

          {/* Análisis por tipo */}
          <div style={{
            backgroundColor: 'white',
            padding: '1.5rem',
            borderRadius: '0.5rem',
            boxShadow: '0 1px 3px rgba(0,0,0,0.1)'
          }}>
            <h3 style={{ margin: '0 0 1rem 0', fontSize: '1.25rem', fontWeight: '600' }}>
              🔍 Actividad de Análisis
            </h3>
            {stats?.by_type ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                {Object.entries(stats.by_type).map(([type, count]) => {
                  const typeIcons = {
                    'SSL_TLS': '🔒',
                    'SSH': '🖥️',
                    'WEB': '🌐',
                    'FULL': '🔍'
                  };
                  
                  const maxCount = Math.max(...Object.values(stats.by_type));
                  const percentage = maxCount > 0 ? (count / maxCount) * 100 : 0;
                  
                  return (
                    <div key={type} style={{ position: 'relative' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.25rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          <span>{typeIcons[type] || '📊'}</span>
                          <span style={{ fontWeight: '500' }}>{type}</span>
                        </div>
                        <span style={{ fontWeight: 'bold', color: '#4f46e5' }}>{count}</span>
                      </div>
                      <div style={{
                        width: '100%',
                        height: '6px',
                        backgroundColor: '#e5e7eb',
                        borderRadius: '3px',
                        overflow: 'hidden'
                      }}>
                        <div style={{
                          width: `${percentage}%`,
                          height: '100%',
                          backgroundColor: '#4f46e5',
                          borderRadius: '3px',
                          transition: 'width 0.5s ease-in-out'
                        }} />
                      </div>
                    </div>
                  );
                })}
                
                <div style={{ marginTop: '1rem', padding: '0.75rem', backgroundColor: '#f8fafc', borderRadius: '0.5rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: '0.875rem', color: '#6b7280' }}>Total ejecutados:</span>
                    <span style={{ fontWeight: 'bold', color: '#1f2937' }}>
                      {Object.values(stats.by_type).reduce((a, b) => a + b, 0)}
                    </span>
                  </div>
                </div>
              </div>
            ) : (
              <div style={{ textAlign: 'center', color: '#6b7280', padding: '2rem' }}>
                <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>📈</div>
                <p>No hay datos de análisis</p>
              </div>
            )}
          </div>
        </div>

        {/* Certificados recientes mejorados */}
        <div style={{
          backgroundColor: 'white',
          padding: '1.5rem',
          borderRadius: '0.5rem',
          boxShadow: '0 1px 3px rgba(0,0,0,0.1)'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h3 style={{ margin: 0, fontSize: '1.25rem', fontWeight: '600' }}>
              🔒 Certificados Monitoreados
            </h3>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <span style={{
                padding: '0.25rem 0.5rem',
                backgroundColor: '#f0f9ff',
                color: '#0c4a6e',
                borderRadius: '0.25rem',
                fontSize: '0.75rem'
              }}>
                {certificates.length} mostrados
              </span>
            </div>
          </div>
          {certificates.length > 0 ? (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ backgroundColor: '#f9fafb' }}>
                    <th style={{ padding: '0.75rem', textAlign: 'left', borderBottom: '2px solid #e5e7eb', fontSize: '0.875rem' }}>
                      Target
                    </th>
                    <th style={{ padding: '0.75rem', textAlign: 'left', borderBottom: '2px solid #e5e7eb', fontSize: '0.875rem' }}>
                      Puerto/Protocolo
                    </th>
                    <th style={{ padding: '0.75rem', textAlign: 'left', borderBottom: '2px solid #e5e7eb', fontSize: '0.875rem' }}>
                      Cliente
                    </th>
                    <th style={{ padding: '0.75rem', textAlign: 'center', borderBottom: '2px solid #e5e7eb', fontSize: '0.875rem' }}>
                      Estado
                    </th>
                    <th style={{ padding: '0.75rem', textAlign: 'center', borderBottom: '2px solid #e5e7eb', fontSize: '0.875rem' }}>
                      Última Verificación
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {certificates.map((cert, index) => {
                    const formatLastCheck = (vitality) => {
                      if (!vitality || !vitality.fecha_verificacion) return 'Nunca';
                      const date = new Date(vitality.fecha_verificacion);
                      const now = new Date();
                      const diffHours = Math.floor((now - date) / (1000 * 60 * 60));
                      
                      if (diffHours < 1) return 'Hace menos de 1h';
                      if (diffHours < 24) return `Hace ${diffHours}h`;
                      return `Hace ${Math.floor(diffHours / 24)}d`;
                    };

                    return (
                      <tr key={cert.id} style={{
                        backgroundColor: index % 2 === 0 ? 'white' : '#f9fafb'
                      }}>
                        <td style={{ padding: '0.75rem', borderBottom: '1px solid #e5e7eb' }}>
                          <div style={{ display: 'flex', flexDirection: 'column' }}>
                            <code style={{ 
                              backgroundColor: '#f3f4f6', 
                              padding: '0.25rem 0.5rem', 
                              borderRadius: '0.25rem',
                              fontSize: '0.75rem',
                              fontWeight: '500'
                            }}>
                              {cert.ip || cert.url}
                            </code>
                            {cert.nombre_certificado && (
                              <span style={{ fontSize: '0.75rem', color: '#6b7280', marginTop: '0.25rem' }}>
                                {cert.nombre_certificado}
                              </span>
                            )}
                          </div>
                        </td>
                        <td style={{ padding: '0.75rem', borderBottom: '1px solid #e5e7eb' }}>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                            <span style={{
                              padding: '0.25rem 0.5rem',
                              backgroundColor: '#e0e7ff',
                              color: '#3730a3',
                              borderRadius: '0.25rem',
                              fontSize: '0.75rem',
                              fontWeight: '500'
                            }}>
                              :{cert.puerto}
                            </span>
                            <span style={{
                              padding: '0.25rem 0.5rem',
                              backgroundColor: '#dbeafe',
                              color: '#1e40af',
                              borderRadius: '0.25rem',
                              fontSize: '0.625rem'
                            }}>
                              {cert.protocolo}
                            </span>
                          </div>
                        </td>
                        <td style={{ padding: '0.75rem', borderBottom: '1px solid #e5e7eb', fontSize: '0.875rem' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            <div style={{
                              width: '8px',
                              height: '8px',
                              borderRadius: '50%',
                              backgroundColor: '#4f46e5'
                            }} />
                            {cert.cliente_nombre || 'Sin cliente'}
                          </div>
                        </td>
                        <td style={{ padding: '0.75rem', borderBottom: '1px solid #e5e7eb', textAlign: 'center' }}>
                          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.25rem' }}>
                            <span style={{
                              padding: '0.25rem 0.75rem',
                              backgroundColor: cert.latest_vitality?.estado === 'activo' ? '#dcfce7' : '#fef2f2',
                              color: cert.latest_vitality?.estado === 'activo' ? '#16a34a' : '#dc2626',
                              borderRadius: '1rem',
                              fontSize: '0.75rem',
                              fontWeight: '500'
                            }}>
                              {cert.latest_vitality?.estado === 'activo' ? '🟢 UP' : '🔴 DOWN'}
                            </span>
                            {cert.latest_vitality?.tiempo_respuesta && (
                              <span style={{ fontSize: '0.625rem', color: '#6b7280' }}>
                                {cert.latest_vitality.tiempo_respuesta}ms
                              </span>
                            )}
                          </div>
                        </td>
                        <td style={{ padding: '0.75rem', borderBottom: '1px solid #e5e7eb', textAlign: 'center' }}>
                          <div style={{ fontSize: '0.75rem', color: '#6b7280' }}>
                            {formatLastCheck(cert.latest_vitality)}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : (
            <div style={{ textAlign: 'center', color: '#6b7280', padding: '3rem' }}>
              <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>🔒</div>
              <h4 style={{ margin: '0 0 0.5rem 0' }}>No hay certificados registrados</h4>
              <p style={{ margin: 0, fontSize: '0.875rem' }}>
                Agrega tu primer certificado para comenzar el monitoreo
              </p>
            </div>
          )}
        </div>
      </div>
    </Layout>
  );
};

export default Dashboard;