import React, { useState, useEffect } from 'react';
import Layout from './Layout';
import { AuthService } from '../services/auth';

const Profile = () => {
  const [user, setUser] = useState(null);
  const [showMFASetup, setShowMFASetup] = useState(false);
  const [showMFADisable, setShowMFADisable] = useState(false);
  const [mfaData, setMfaData] = useState(null);
  const [formData, setFormData] = useState({
    password: '',
    mfaToken: ''
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  useEffect(() => {
    loadUserProfile();
  }, []);

  const loadUserProfile = async () => {
    try {
      const response = await AuthService.getProfile();
      setUser(response.user);
    } catch (error) {
      console.error('Error loading profile:', error);
    }
  };

  const handleSetupMFA = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await AuthService.setupMFA(formData.password);
      setMfaData(response);
      setFormData({ password: '', mfaToken: '' });
    } catch (error) {
      setError(error.response?.data?.error || 'Error al configurar MFA');
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyAndEnable = async (e) => {
    e.preventDefault();
    if (!formData.mfaToken || formData.mfaToken.length !== 6) {
      setError('Ingrese un código válido de 6 dígitos');
      return;
    }

    setLoading(true);
    setError('');

    try {
      // Verificar el código TOTP antes de habilitar
      const response = await AuthService.verifyMFA(user.id, formData.mfaToken);
      
      setSuccess('🎉 MFA configurado exitosamente!');
      setShowMFASetup(false);
      setMfaData(null);
      setFormData({ password: '', mfaToken: '' });
      
      // Recargar perfil para mostrar MFA habilitado
      await loadUserProfile();
    } catch (error) {
      setError('Código MFA incorrecto. Verifique su aplicación autenticadora.');
    } finally {
      setLoading(false);
    }
  };

  const handleDisableMFA = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      await AuthService.disableMFA(formData.password, formData.mfaToken);
      setSuccess('MFA deshabilitado exitosamente');
      setShowMFADisable(false);
      setFormData({ password: '', mfaToken: '' });
      await loadUserProfile();
    } catch (error) {
      setError(error.response?.data?.error || 'Error al deshabilitar MFA');
    } finally {
      setLoading(false);
    }
  };

  const resetModals = () => {
    setShowMFASetup(false);
    setShowMFADisable(false);
    setMfaData(null);
    setFormData({ password: '', mfaToken: '' });
    setError('');
    setSuccess('');
  };

  if (!user) {
    return (
      <Layout>
        <div style={{ textAlign: 'center', padding: '2rem' }}>
          <div style={{ fontSize: '1.5rem' }}>🔄</div>
          <p>Cargando perfil...</p>
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div style={{ maxWidth: '800px', margin: '0 auto' }}>
        {/* Header */}
        <div style={{ marginBottom: '2rem' }}>
          <h2 style={{ fontSize: '1.875rem', fontWeight: 'bold', color: '#1f2937', margin: 0 }}>
            👤 Perfil de Usuario
          </h2>
          <p style={{ color: '#6b7280', margin: '0.5rem 0 0 0' }}>
            Configuración de cuenta y seguridad
          </p>
        </div>

        {/* Mensajes */}
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

        {success && (
          <div style={{
            backgroundColor: '#f0fdf4',
            border: '1px solid #bbf7d0',
            color: '#16a34a',
            padding: '0.75rem',
            borderRadius: '0.375rem',
            marginBottom: '1rem'
          }}>
            {success}
          </div>
        )}

        <div style={{ display: 'grid', gap: '2rem' }}>
          {/* Información del usuario */}
          <div style={{
            backgroundColor: 'white',
            padding: '2rem',
            borderRadius: '0.5rem',
            boxShadow: '0 1px 3px rgba(0,0,0,0.1)'
          }}>
            <h3 style={{ margin: '0 0 1.5rem 0', fontSize: '1.25rem', fontWeight: '600' }}>
              Información de la Cuenta
            </h3>
            
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
              gap: '1rem'
            }}>
              <div>
                <label style={{ fontSize: '0.875rem', fontWeight: '500', color: '#6b7280' }}>
                  Email
                </label>
                <div style={{
                  padding: '0.75rem',
                  backgroundColor: '#f9fafb',
                  border: '1px solid #e5e7eb',
                  borderRadius: '0.375rem',
                  marginTop: '0.25rem'
                }}>
                  {user.email}
                </div>
              </div>
              
              <div>
                <label style={{ fontSize: '0.875rem', fontWeight: '500', color: '#6b7280' }}>
                  Nombre
                </label>
                <div style={{
                  padding: '0.75rem',
                  backgroundColor: '#f9fafb',
                  border: '1px solid #e5e7eb',
                  borderRadius: '0.375rem',
                  marginTop: '0.25rem'
                }}>
                  {user.nombre_usuario}
                </div>
              </div>
              
              <div>
                <label style={{ fontSize: '0.875rem', fontWeight: '500', color: '#6b7280' }}>
                  Rol
                </label>
                <div style={{
                  padding: '0.75rem',
                  backgroundColor: '#f9fafb',
                  border: '1px solid #e5e7eb',
                  borderRadius: '0.375rem',
                  marginTop: '0.25rem'
                }}>
                  <span style={{
                    padding: '0.25rem 0.5rem',
                    backgroundColor: '#dbeafe',
                    color: '#1e40af',
                    borderRadius: '0.25rem',
                    fontSize: '0.875rem'
                  }}>
                    {user.rol}
                  </span>
                </div>
              </div>
              
              <div>
                <label style={{ fontSize: '0.875rem', fontWeight: '500', color: '#6b7280' }}>
                  Último Login
                </label>
                <div style={{
                  padding: '0.75rem',
                  backgroundColor: '#f9fafb',
                  border: '1px solid #e5e7eb',
                  borderRadius: '0.375rem',
                  marginTop: '0.25rem',
                  fontSize: '0.875rem'
                }}>
                  {user.ultimo_login ? new Date(user.ultimo_login).toLocaleString('es-CL') : 'N/A'}
                </div>
              </div>
            </div>
          </div>

          {/* Configuración MFA */}
          <div style={{
            backgroundColor: 'white',
            padding: '2rem',
            borderRadius: '0.5rem',
            boxShadow: '0 1px 3px rgba(0,0,0,0.1)'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '1.25rem', fontWeight: '600' }}>
                  🔐 Autenticación Multi-Factor (MFA)
                </h3>
                <p style={{ margin: '0.5rem 0 0 0', fontSize: '0.875rem', color: '#6b7280' }}>
                  Agregue una capa adicional de seguridad a su cuenta
                </p>
              </div>
              
              <div style={{
                padding: '0.5rem 1rem',
                backgroundColor: user.mfa_enabled ? '#dcfce7' : '#fef3c7',
                color: user.mfa_enabled ? '#16a34a' : '#d97706',
                borderRadius: '0.5rem',
                fontSize: '0.875rem',
                fontWeight: '500'
              }}>
                {user.mfa_enabled ? '🟢 MFA Habilitado' : '🟡 MFA Deshabilitado'}
              </div>
            </div>

            <div style={{
              padding: '1.5rem',
              backgroundColor: '#f9fafb',
              borderRadius: '0.5rem',
              border: '1px solid #e5e7eb',
              marginBottom: '1.5rem'
            }}>
              <h4 style={{ margin: '0 0 0.5rem 0', fontSize: '1rem', fontWeight: '500' }}>
                ¿Qué es MFA?
              </h4>
              <p style={{ margin: 0, fontSize: '0.875rem', color: '#6b7280', lineHeight: '1.5' }}>
                La autenticación multi-factor requiere que ingrese un código de 6 dígitos desde una 
                aplicación autenticadora (como Google Authenticator, Authy, etc.) cada vez que inicie sesión, 
                además de su contraseña habitual.
              </p>
            </div>

            {!user.mfa_enabled ? (
              <button
                onClick={() => setShowMFASetup(true)}
                style={{
                  padding: '0.75rem 1.5rem',
                  backgroundColor: '#059669',
                  color: 'white',
                  border: 'none',
                  borderRadius: '0.5rem',
                  cursor: 'pointer',
                  fontWeight: '500',
                  fontSize: '0.875rem'
                }}
              >
                🔒 Habilitar MFA
              </button>
            ) : (
              <button
                onClick={() => setShowMFADisable(true)}
                style={{
                  padding: '0.75rem 1.5rem',
                  backgroundColor: '#dc2626',
                  color: 'white',
                  border: 'none',
                  borderRadius: '0.5rem',
                  cursor: 'pointer',
                  fontWeight: '500',
                  fontSize: '0.875rem'
                }}
              >
                ❌ Deshabilitar MFA
              </button>
            )}
          </div>
        </div>

        {/* Modal para configurar MFA */}
        {showMFASetup && (
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
              {!mfaData ? (
                // Paso 1: Solicitar contraseña
                <>
                  <h3 style={{ margin: '0 0 1.5rem 0', fontSize: '1.5rem', fontWeight: '600' }}>
                    🔐 Configurar MFA
                  </h3>
                  
                  <form onSubmit={handleSetupMFA}>
                    <div style={{ marginBottom: '1.5rem' }}>
                      <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500' }}>
                        Confirme su contraseña actual
                      </label>
                      <input
                        type="password"
                        value={formData.password}
                        onChange={(e) => setFormData({...formData, password: e.target.value})}
                        placeholder="••••••••"
                        required
                        style={{
                          width: '100%',
                          padding: '0.75rem',
                          border: '1px solid #d1d5db',
                          borderRadius: '0.375rem'
                        }}
                      />
                    </div>

                    <div style={{ display: 'flex', gap: '1rem', justifyContent: 'flex-end' }}>
                      <button
                        type="button"
                        onClick={resetModals}
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
                        {loading ? 'Configurando...' : 'Continuar'}
                      </button>
                    </div>
                  </form>
                </>
              ) : (
                // Paso 2: Mostrar QR y verificar código
                <>
                  <h3 style={{ margin: '0 0 1.5rem 0', fontSize: '1.5rem', fontWeight: '600' }}>
                    📱 Configurar Aplicación Autenticadora
                  </h3>

                  <div style={{ marginBottom: '1.5rem' }}>
                    <h4 style={{ margin: '0 0 1rem 0', fontSize: '1rem', fontWeight: '500' }}>
                      Paso 1: Escanee el código QR
                    </h4>
                    <div style={{ textAlign: 'center', marginBottom: '1rem' }}>
                      <img 
                        src={mfaData.qr_code} 
                        alt="QR Code para MFA" 
                        style={{ maxWidth: '200px', border: '1px solid #e5e7eb', borderRadius: '0.5rem' }}
                      />
                    </div>
                    <p style={{ fontSize: '0.875rem', color: '#6b7280', textAlign: 'center' }}>
                      Use Google Authenticator, Authy u otra app TOTP para escanear este código
                    </p>
                  </div>

                  <div style={{ marginBottom: '1.5rem' }}>
                    <h4 style={{ margin: '0 0 0.5rem 0', fontSize: '1rem', fontWeight: '500' }}>
                      Código manual (alternativa):
                    </h4>
                    <div style={{
                      padding: '0.75rem',
                      backgroundColor: '#f3f4f6',
                      borderRadius: '0.375rem',
                      fontSize: '0.875rem',
                      wordBreak: 'break-all'
                    }}>
                      <strong>{mfaData.secret}</strong>
                    </div>
                  </div>

                  <form onSubmit={handleVerifyAndEnable}>
                    <div style={{ marginBottom: '1.5rem' }}>
                      <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500' }}>
                        Paso 2: Ingrese el código de 6 dígitos
                      </label>
                      <input
                        type="text"
                        value={formData.mfaToken}
                        onChange={(e) => setFormData({...formData, mfaToken: e.target.value})}
                        placeholder="123456"
                        maxLength="6"
                        required
                        style={{
                          width: '100%',
                          padding: '0.75rem',
                          border: '1px solid #d1d5db',
                          borderRadius: '0.375rem',
                          textAlign: 'center',
                          fontSize: '1.5rem',
                          letterSpacing: '0.5rem'
                        }}
                      />
                    </div>

                    <div style={{ display: 'flex', gap: '1rem', justifyContent: 'flex-end' }}>
                      <button
                        type="button"
                        onClick={resetModals}
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
                        {loading ? 'Verificando...' : 'Habilitar MFA'}
                      </button>
                    </div>
                  </form>
                </>
              )}
            </div>
          </div>
        )}

        {/* Modal para deshabilitar MFA */}
        {showMFADisable && (
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
              maxWidth: '400px'
            }}>
              <h3 style={{ margin: '0 0 1.5rem 0', fontSize: '1.5rem', fontWeight: '600' }}>
                ⚠️ Deshabilitar MFA
              </h3>

              <div style={{
                backgroundColor: '#fef3c7',
                border: '1px solid #f59e0b',
                padding: '1rem',
                borderRadius: '0.375rem',
                marginBottom: '1.5rem'
              }}>
                <p style={{ margin: 0, fontSize: '0.875rem', color: '#92400e' }}>
                  <strong>Advertencia:</strong> Deshabilitar MFA reducirá la seguridad de su cuenta.
                </p>
              </div>

              <form onSubmit={handleDisableMFA}>
                <div style={{ marginBottom: '1rem' }}>
                  <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500' }}>
                    Contraseña actual
                  </label>
                  <input
                    type="password"
                    value={formData.password}
                    onChange={(e) => setFormData({...formData, password: e.target.value})}
                    placeholder="••••••••"
                    required
                    style={{
                      width: '100%',
                      padding: '0.75rem',
                      border: '1px solid #d1d5db',
                      borderRadius: '0.375rem'
                    }}
                  />
                </div>

                <div style={{ marginBottom: '1.5rem' }}>
                  <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500' }}>
                    Código MFA actual
                  </label>
                  <input
                    type="text"
                    value={formData.mfaToken}
                    onChange={(e) => setFormData({...formData, mfaToken: e.target.value})}
                    placeholder="123456"
                    maxLength="6"
                    required
                    style={{
                      width: '100%',
                      padding: '0.75rem',
                      border: '1px solid #d1d5db',
                      borderRadius: '0.375rem',
                      textAlign: 'center',
                      letterSpacing: '0.25rem'
                    }}
                  />
                </div>

                <div style={{ display: 'flex', gap: '1rem', justifyContent: 'flex-end' }}>
                  <button
                    type="button"
                    onClick={resetModals}
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
                    disabled={loading}
                    style={{
                      padding: '0.75rem 1.5rem',
                      backgroundColor: loading ? '#9ca3af' : '#dc2626',
                      color: 'white',
                      border: 'none',
                      borderRadius: '0.375rem',
                      cursor: loading ? 'not-allowed' : 'pointer',
                      fontWeight: '500'
                    }}
                  >
                    {loading ? 'Procesando...' : 'Deshabilitar MFA'}
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

export default Profile;