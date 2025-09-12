import React, { useState, useEffect } from 'react';
import { CertificateService } from '../services/certificates';

const CertificateForm = ({ onClose, onSuccess }) => {
  const [clients, setClients] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [formData, setFormData] = useState({
    cliente: '',
    nombre_certificado: '',
    target_type: 'url', // 'url' o 'ip'
    ip: '',
    url: '',
    puerto: 443,
    protocolo: 'HTTPS',
    frecuencia_analisis: 30
  });

  // URLs y IPs de ejemplo comunes para testing
  const ejemplosComunes = {
    urls: [
      'google.com',
      'github.com', 
      'stackoverflow.com',
      'cloudflare.com',
      'amazon.com',
      'microsoft.com',
      'apple.com',
      'facebook.com',
      'twitter.com',
      'linkedin.com'
    ],
    ips: [
      '8.8.8.8',
      '1.1.1.1',
      '208.67.222.222',
      '208.67.220.220'
    ]
  };

  useEffect(() => {
    loadClients();
  }, []);

  const loadClients = async () => {
    try {
      const response = await fetch('http://localhost:8000/api/clients/');
      const data = await response.json();
      setClients(data.results || data);
    } catch (error) {
      console.error('Error loading clients:', error);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const certData = {
        cliente: formData.cliente,
        nombre_certificado: formData.nombre_certificado || null,
        ip: formData.target_type === 'ip' ? formData.ip : null,
        url: formData.target_type === 'url' ? formData.url : null,
        puerto: parseInt(formData.puerto),
        protocolo: formData.protocolo,
        frecuencia_analisis: parseInt(formData.frecuencia_analisis)
      };

      await CertificateService.createCertificate(certData);
      onSuccess && onSuccess();
      onClose && onClose();
    } catch (error) {
      setError(error.response?.data?.error || 'Error al crear certificado');
    } finally {
      setLoading(false);
    }
  };

  const handleEjemploClick = (valor) => {
    if (formData.target_type === 'url') {
      setFormData({...formData, url: valor});
    } else {
      setFormData({...formData, ip: valor});
    }
  };

  const ejemplos = formData.target_type === 'url' ? ejemplosComunes.urls : ejemplosComunes.ips;

  return (
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
        maxWidth: '600px',
        maxHeight: '90vh',
        overflowY: 'auto'
      }}>
        <h3 style={{ margin: '0 0 1.5rem 0', fontSize: '1.5rem', fontWeight: '600' }}>
          🔒 Agregar Nuevo Certificado
        </h3>

        {error && (
          <div style={{
            backgroundColor: '#fef2f2',
            border: '1px solid #fecaca',
            color: '#dc2626',
            padding: '0.75rem',
            borderRadius: '0.375rem',
            marginBottom: '1rem'
          }}>
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit}>
          {/* Cliente */}
          <div style={{ marginBottom: '1rem' }}>
            <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500' }}>
              Cliente *
            </label>
            <select
              value={formData.cliente}
              onChange={(e) => setFormData({...formData, cliente: e.target.value})}
              required
              style={{
                width: '100%',
                padding: '0.75rem',
                border: '1px solid #d1d5db',
                borderRadius: '0.375rem'
              }}
            >
              <option value="">Seleccionar cliente</option>
              {clients.map(client => (
                <option key={client.id} value={client.id}>
                  {client.name}
                </option>
              ))}
            </select>
          </div>

          {/* Nombre del certificado (opcional) */}
          <div style={{ marginBottom: '1rem' }}>
            <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500' }}>
              Nombre del Certificado (opcional)
            </label>
            <input
              type="text"
              value={formData.nombre_certificado}
              onChange={(e) => setFormData({...formData, nombre_certificado: e.target.value})}
              placeholder="ej: Certificado principal, Web corporativa..."
              style={{
                width: '100%',
                padding: '0.75rem',
                border: '1px solid #d1d5db',
                borderRadius: '0.375rem'
              }}
            />
          </div>

          {/* Tipo de target */}
          <div style={{ marginBottom: '1rem' }}>
            <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500' }}>
              Tipo de Destino *
            </label>
            <div style={{ display: 'flex', gap: '1rem' }}>
              <label style={{ display: 'flex', alignItems: 'center', cursor: 'pointer' }}>
                <input
                  type="radio"
                  value="url"
                  checked={formData.target_type === 'url'}
                  onChange={(e) => setFormData({...formData, target_type: e.target.value})}
                  style={{ marginRight: '0.5rem' }}
                />
                🌐 URL/Dominio
              </label>
              <label style={{ display: 'flex', alignItems: 'center', cursor: 'pointer' }}>
                <input
                  type="radio"
                  value="ip"
                  checked={formData.target_type === 'ip'}
                  onChange={(e) => setFormData({...formData, target_type: e.target.value})}
                  style={{ marginRight: '0.5rem' }}
                />
                🖥️ Dirección IP
              </label>
            </div>
          </div>

          {/* URL o IP */}
          <div style={{ marginBottom: '1rem' }}>
            <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500' }}>
              {formData.target_type === 'url' ? '🌐 URL/Dominio *' : '🖥️ Dirección IP *'}
            </label>
            {formData.target_type === 'url' ? (
              <input
                type="text"
                value={formData.url}
                onChange={(e) => setFormData({...formData, url: e.target.value})}
                placeholder="example.com (sin https://)"
                required
                style={{
                  width: '100%',
                  padding: '0.75rem',
                  border: '1px solid #d1d5db',
                  borderRadius: '0.375rem'
                }}
              />
            ) : (
              <input
                type="text"
                value={formData.ip}
                onChange={(e) => setFormData({...formData, ip: e.target.value})}
                placeholder="192.168.1.1"
                required
                style={{
                  width: '100%',
                  padding: '0.75rem',
                  border: '1px solid #d1d5db',
                  borderRadius: '0.375rem'
                }}
              />
            )}
            
            {/* Ejemplos comunes */}
            <div style={{ marginTop: '0.5rem' }}>
              <small style={{ color: '#6b7280', marginBottom: '0.5rem', display: 'block' }}>
                📋 Ejemplos comunes (click para usar):
              </small>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                {ejemplos.slice(0, 6).map(ejemplo => (
                  <button
                    key={ejemplo}
                    type="button"
                    onClick={() => handleEjemploClick(ejemplo)}
                    style={{
                      padding: '0.25rem 0.5rem',
                      backgroundColor: '#f3f4f6',
                      border: '1px solid #d1d5db',
                      borderRadius: '0.25rem',
                      cursor: 'pointer',
                      fontSize: '0.75rem',
                      color: '#4b5563'
                    }}
                  >
                    {ejemplo}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Puerto y Protocolo */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
            <div>
              <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500' }}>
                Puerto *
              </label>
              <input
                type="number"
                value={formData.puerto}
                onChange={(e) => setFormData({...formData, puerto: e.target.value})}
                min="1"
                max="65535"
                required
                style={{
                  width: '100%',
                  padding: '0.75rem',
                  border: '1px solid #d1d5db',
                  borderRadius: '0.375rem'
                }}
              />
              <small style={{ color: '#6b7280' }}>
                Común: 443 (HTTPS), 22 (SSH), 587 (SMTP)
              </small>
            </div>

            <div>
              <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500' }}>
                Protocolo *
              </label>
              <select
                value={formData.protocolo}
                onChange={(e) => setFormData({...formData, protocolo: e.target.value})}
                style={{
                  width: '100%',
                  padding: '0.75rem',
                  border: '1px solid #d1d5db',
                  borderRadius: '0.375rem'
                }}
              >
                <option value="HTTPS">HTTPS</option>
                <option value="TLS">TLS</option>
                <option value="SSH">SSH</option>
                <option value="SMTP">SMTP</option>
                <option value="IMAP">IMAP</option>
                <option value="POP3">POP3</option>
                <option value="OTHER">Otro</option>
              </select>
            </div>
          </div>

          {/* Frecuencia de análisis */}
          <div style={{ marginBottom: '1.5rem' }}>
            <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500' }}>
              Frecuencia de Análisis
            </label>
            <select
              value={formData.frecuencia_analisis}
              onChange={(e) => setFormData({...formData, frecuencia_analisis: e.target.value})}
              style={{
                width: '100%',
                padding: '0.75rem',
                border: '1px solid #d1d5db',
                borderRadius: '0.375rem'
              }}
            >
              <option value="7">Semanal (7 días)</option>
              <option value="15">Quincenal (15 días)</option>
              <option value="30">Mensual (30 días)</option>
            </select>
            <small style={{ color: '#6b7280' }}>
              Con qué frecuencia se ejecutará el análisis automático
            </small>
          </div>

          {/* Información adicional */}
          <div style={{
            backgroundColor: '#f0f9ff',
            border: '1px solid #bae6fd',
            padding: '1rem',
            borderRadius: '0.5rem',
            marginBottom: '1.5rem'
          }}>
            <h4 style={{ margin: '0 0 0.5rem 0', fontSize: '0.875rem', fontWeight: '500', color: '#0c4a6e' }}>
              ℹ️ ¿Qué se analizará?
            </h4>
            <ul style={{ margin: 0, paddingLeft: '1rem', fontSize: '0.75rem', color: '#0c4a6e' }}>
              <li>Configuración del certificado SSL/TLS</li>
              <li>Vulnerabilidades conocidas (Heartbleed, POODLE, etc.)</li>
              <li>Protocolos y cifrados soportados</li>
              <li>Cadena de certificación completa</li>
              <li>Headers de seguridad web</li>
              <li>Fechas de expiración y validez</li>
            </ul>
          </div>

          {/* Botones */}
          <div style={{ display: 'flex', gap: '1rem', justifyContent: 'flex-end' }}>
            <button
              type="button"
              onClick={onClose}
              disabled={loading}
              style={{
                padding: '0.75rem 1.5rem',
                backgroundColor: 'transparent',
                color: '#6b7280',
                border: '1px solid #d1d5db',
                borderRadius: '0.375rem',
                cursor: loading ? 'not-allowed' : 'pointer'
              }}
            >
              Cancelar
            </button>
            <button
              type="submit"
              disabled={loading}
              style={{
                padding: '0.75rem 1.5rem',
                backgroundColor: loading ? '#9ca3af' : '#059669',
                color: 'white',
                border: 'none',
                borderRadius: '0.375rem',
                cursor: loading ? 'not-allowed' : 'pointer',
                fontWeight: '500'
              }}
            >
              {loading ? '🔄 Creando...' : '✅ Crear y Analizar'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default CertificateForm;