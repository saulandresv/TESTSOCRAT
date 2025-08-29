import React, { useState, useEffect } from 'react';
import Layout from './Layout';
import CertificateForm from './CertificateForm';
import { CertificateService } from '../services/certificates';
import { AnalysisService } from '../services/analysis';

const Certificates = () => {
  const [certificates, setCertificates] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [selectedCerts, setSelectedCerts] = useState([]);
  const [filters, setFilters] = useState({
    search: '',
    protocol: '',
    client: '',
    status: ''
  });

  useEffect(() => {
    loadCertificates();
  }, [filters]);

  const loadCertificates = async () => {
    try {
      setLoading(true);
      const params = {};
      if (filters.search) params.search = filters.search;
      if (filters.protocol) params.protocol = filters.protocol;
      if (filters.client) params.client = filters.client;
      if (filters.status) params.status = filters.status;

      const response = await CertificateService.getCertificates(params);
      setCertificates(response.results || response);
    } catch (error) {
      console.error('Error loading certificates:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleCheckVitality = async (certId) => {
    try {
      await CertificateService.checkVitality(certId);
      loadCertificates(); // Recargar para mostrar nuevo estado
    } catch (error) {
      console.error('Error checking vitality:', error);
    }
  };

  const handleRunAnalysis = async () => {
    if (selectedCerts.length === 0) {
      alert('Selecciona al menos un certificado para analizar');
      return;
    }

    try {
      await AnalysisService.runAnalysis(selectedCerts, 'SSL_TLS');
      alert(`Análisis iniciado para ${selectedCerts.length} certificado(s)`);
      setSelectedCerts([]);
    } catch (error) {
      console.error('Error running analysis:', error);
      alert('Error al ejecutar análisis');
    }
  };

  const handleSelectCert = (certId) => {
    setSelectedCerts(prev => {
      if (prev.includes(certId)) {
        return prev.filter(id => id !== certId);
      } else {
        return [...prev, certId];
      }
    });
  };

  const handleSelectAll = () => {
    if (selectedCerts.length === certificates.length) {
      setSelectedCerts([]);
    } else {
      setSelectedCerts(certificates.map(cert => cert.id));
    }
  };

  const formatLastCheck = (vitality) => {
    if (!vitality) return 'Nunca';
    const date = new Date(vitality.hora);
    return date.toLocaleString('es-CL');
  };

  const getExpirationStatus = (cert) => {
    if (!cert.fecha_expiracion) return { color: '#6b7280', text: 'No disponible' };
    
    const expDate = new Date(cert.fecha_expiracion);
    const today = new Date();
    const daysUntilExpiry = Math.ceil((expDate - today) / (1000 * 60 * 60 * 24));
    
    if (daysUntilExpiry < 0) {
      return { color: '#dc2626', text: `Expirado hace ${Math.abs(daysUntilExpiry)} días` };
    } else if (daysUntilExpiry <= 7) {
      return { color: '#dc2626', text: `Expira en ${daysUntilExpiry} días` };
    } else if (daysUntilExpiry <= 30) {
      return { color: '#f59e0b', text: `Expira en ${daysUntilExpiry} días` };
    } else {
      return { color: '#059669', text: `${daysUntilExpiry} días restantes` };
    }
  };

  if (loading) {
    return (
      <Layout>
        <div style={{ textAlign: 'center', padding: '2rem' }}>
          <div style={{ fontSize: '1.5rem' }}>🔄</div>
          <p>Cargando certificados...</p>
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
              🔒 Certificados SSL/TLS
            </h2>
            <p style={{ color: '#6b7280', margin: '0.5rem 0 0 0' }}>
              Gestión y monitoreo de certificados digitales
            </p>
          </div>
          
          <div style={{ display: 'flex', gap: '1rem' }}>
            <button
              onClick={() => setShowCreateModal(true)}
              style={{
                padding: '0.75rem 1.5rem',
                backgroundColor: '#4f46e5',
                color: 'white',
                border: 'none',
                borderRadius: '0.5rem',
                cursor: 'pointer',
                fontWeight: '500'
              }}
            >
              ➕ Nuevo Certificado
            </button>
            
            {selectedCerts.length > 0 && (
              <button
                onClick={handleRunAnalysis}
                style={{
                  padding: '0.75rem 1.5rem',
                  backgroundColor: '#059669',
                  color: 'white',
                  border: 'none',
                  borderRadius: '0.5rem',
                  cursor: 'pointer',
                  fontWeight: '500'
                }}
              >
                🔍 Analizar ({selectedCerts.length})
              </button>
            )}
          </div>
        </div>

        {/* Filtros */}
        <div style={{
          backgroundColor: 'white',
          padding: '1.5rem',
          borderRadius: '0.5rem',
          boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
          marginBottom: '1.5rem'
        }}>
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
            gap: '1rem'
          }}>
            <input
              type="text"
              placeholder="🔍 Buscar por IP/URL..."
              value={filters.search}
              onChange={(e) => setFilters({...filters, search: e.target.value})}
              style={{
                padding: '0.5rem',
                border: '1px solid #d1d5db',
                borderRadius: '0.375rem'
              }}
            />
            
            <select
              value={filters.protocol}
              onChange={(e) => setFilters({...filters, protocol: e.target.value})}
              style={{
                padding: '0.5rem',
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

            <select
              value={filters.status}
              onChange={(e) => setFilters({...filters, status: e.target.value})}
              style={{
                padding: '0.5rem',
                border: '1px solid #d1d5db',
                borderRadius: '0.375rem'
              }}
            >
              <option value="">Todos los estados</option>
              <option value="up">Activos</option>
              <option value="down">Inactivos</option>
            </select>
          </div>
        </div>

        {/* Estadísticas rápidas */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
          gap: '1rem',
          marginBottom: '2rem'
        }}>
          <div style={{
            backgroundColor: 'white',
            padding: '1rem',
            borderRadius: '0.5rem',
            textAlign: 'center',
            boxShadow: '0 1px 3px rgba(0,0,0,0.1)'
          }}>
            <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#4f46e5' }}>
              {certificates.length}
            </div>
            <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>
              Total Certificados
            </div>
          </div>
          
          <div style={{
            backgroundColor: 'white',
            padding: '1rem',
            borderRadius: '0.5rem',
            textAlign: 'center',
            boxShadow: '0 1px 3px rgba(0,0,0,0.1)'
          }}>
            <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#059669' }}>
              {certificates.filter(c => c.latest_vitality?.estado === 'activo').length}
            </div>
            <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>
              Activos
            </div>
          </div>
          
          <div style={{
            backgroundColor: 'white',
            padding: '1rem',
            borderRadius: '0.5rem',
            textAlign: 'center',
            boxShadow: '0 1px 3px rgba(0,0,0,0.1)'
          }}>
            <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#dc2626' }}>
              {certificates.filter(c => {
                if (!c.fecha_expiracion) return false;
                const expDate = new Date(c.fecha_expiracion);
                const today = new Date();
                const daysUntilExpiry = Math.ceil((expDate - today) / (1000 * 60 * 60 * 24));
                return daysUntilExpiry <= 30;
              }).length}
            </div>
            <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>
              Por Expirar
            </div>
          </div>
        </div>

        {/* Tabla de certificados */}
        <div style={{
          backgroundColor: 'white',
          borderRadius: '0.5rem',
          boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
          overflow: 'hidden'
        }}>
          {certificates.length > 0 ? (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead style={{ backgroundColor: '#f9fafb' }}>
                  <tr>
                    <th style={{ padding: '1rem', textAlign: 'left' }}>
                      <input
                        type="checkbox"
                        checked={selectedCerts.length === certificates.length}
                        onChange={handleSelectAll}
                        style={{ marginRight: '0.5rem' }}
                      />
                      Target
                    </th>
                    <th style={{ padding: '1rem', textAlign: 'left' }}>Puerto</th>
                    <th style={{ padding: '1rem', textAlign: 'left' }}>Protocolo</th>
                    <th style={{ padding: '1rem', textAlign: 'left' }}>Cliente</th>
                    <th style={{ padding: '1rem', textAlign: 'center' }}>Estado</th>
                    <th style={{ padding: '1rem', textAlign: 'left' }}>Última Verificación</th>
                    <th style={{ padding: '1rem', textAlign: 'left' }}>Expiración</th>
                    <th style={{ padding: '1rem', textAlign: 'center' }}>Acciones</th>
                  </tr>
                </thead>
                <tbody>
                  {certificates.map((cert) => {
                    const expStatus = getExpirationStatus(cert);
                    return (
                      <tr key={cert.id} style={{ borderBottom: '1px solid #e5e7eb' }}>
                        <td style={{ padding: '1rem' }}>
                          <div style={{ display: 'flex', alignItems: 'center' }}>
                            <input
                              type="checkbox"
                              checked={selectedCerts.includes(cert.id)}
                              onChange={() => handleSelectCert(cert.id)}
                              style={{ marginRight: '0.5rem' }}
                            />
                            <code style={{
                              backgroundColor: '#f3f4f6',
                              padding: '0.25rem 0.5rem',
                              borderRadius: '0.25rem',
                              fontSize: '0.875rem'
                            }}>
                              {cert.ip || cert.url}
                            </code>
                          </div>
                        </td>
                        <td style={{ padding: '1rem' }}>
                          <span style={{
                            padding: '0.25rem 0.5rem',
                            backgroundColor: '#e0e7ff',
                            color: '#3730a3',
                            borderRadius: '0.25rem',
                            fontSize: '0.875rem'
                          }}>
                            {cert.puerto}
                          </span>
                        </td>
                        <td style={{ padding: '1rem' }}>
                          <span style={{
                            padding: '0.25rem 0.5rem',
                            backgroundColor: '#dbeafe',
                            color: '#1e40af',
                            borderRadius: '0.25rem',
                            fontSize: '0.75rem'
                          }}>
                            {cert.protocolo}
                          </span>
                        </td>
                        <td style={{ padding: '1rem', fontSize: '0.875rem' }}>
                          {cert.cliente_nombre}
                        </td>
                        <td style={{ padding: '1rem', textAlign: 'center' }}>
                          <span style={{
                            padding: '0.25rem 0.5rem',
                            backgroundColor: cert.latest_vitality?.estado === 'activo' ? '#dcfce7' : '#fef2f2',
                            color: cert.latest_vitality?.estado === 'activo' ? '#16a34a' : '#dc2626',
                            borderRadius: '0.25rem',
                            fontSize: '0.75rem',
                            fontWeight: '500'
                          }}>
                            {cert.latest_vitality?.estado === 'activo' ? '🟢 UP' : '🔴 DOWN'}
                          </span>
                        </td>
                        <td style={{ padding: '1rem', fontSize: '0.875rem', color: '#6b7280' }}>
                          {formatLastCheck(cert.latest_vitality)}
                        </td>
                        <td style={{ padding: '1rem' }}>
                          <span style={{
                            fontSize: '0.75rem',
                            color: expStatus.color,
                            fontWeight: '500'
                          }}>
                            {expStatus.text}
                          </span>
                        </td>
                        <td style={{ padding: '1rem', textAlign: 'center' }}>
                          <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'center' }}>
                            <button
                              onClick={() => handleCheckVitality(cert.id)}
                              style={{
                                padding: '0.25rem 0.5rem',
                                backgroundColor: '#f3f4f6',
                                border: '1px solid #d1d5db',
                                borderRadius: '0.25rem',
                                cursor: 'pointer',
                                fontSize: '0.75rem'
                              }}
                              title="Verificar vitalidad"
                            >
                              🔄
                            </button>
                            <button
                              onClick={() => handleRunAnalysis([cert.id])}
                              style={{
                                padding: '0.25rem 0.5rem',
                                backgroundColor: '#f3f4f6',
                                border: '1px solid #d1d5db',
                                borderRadius: '0.25rem',
                                cursor: 'pointer',
                                fontSize: '0.75rem'
                              }}
                              title="Ejecutar análisis"
                            >
                              🔍
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : (
            <div style={{
              textAlign: 'center',
              padding: '3rem',
              color: '#6b7280'
            }}>
              <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>🔒</div>
              <h3 style={{ margin: '0 0 0.5rem 0' }}>No hay certificados registrados</h3>
              <p style={{ margin: 0 }}>
                Comienza agregando tu primer certificado para monitorear
              </p>
            </div>
          )}
        </div>

        {/* Modal para crear certificado */}
        {showCreateModal && (
          <CertificateForm
            onClose={() => setShowCreateModal(false)}
            onSuccess={loadCertificates}
          />
        )}
      </div>
    </Layout>
  );
};

export default Certificates;