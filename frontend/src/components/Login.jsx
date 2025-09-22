import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { AuthService } from '../services/auth';

const Login = () => {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    mfaCode: ''
  });
  const [step, setStep] = useState('login'); // 'login' | 'mfa' | 'mfa-setup'
  const [userId, setUserId] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [mfaData, setMfaData] = useState(null); // Para datos del QR code
  const navigate = useNavigate();

  const handleInputChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      console.log('🔍 Iniciando login con:', formData.email);
      const response = await AuthService.login(formData.email, formData.password);
      console.log('✅ Respuesta del login:', response);

      if (response.mfa_required) {
        // Requiere MFA
        console.log('🔒 MFA requerido');
        setStep('mfa');
        setUserId(response.user_id);
      } else if (response.mfa_setup_required) {
        // Requiere configurar MFA
        console.log('⚙️ MFA setup requerido');
        setError(''); // Limpiar error ya que vamos a mostrar setup
        handleMFASetupRequired();
      } else {
        // Login exitoso sin MFA
        console.log('💾 Guardando datos de auth...');
        AuthService.saveAuthData(response);
        console.log('🚀 Navegando a dashboard...');

        // Usar window.location como backup
        try {
          navigate('/dashboard');
        } catch (navError) {
          console.log('❌ Error con navigate, usando window.location');
          window.location.href = '/dashboard';
        }
      }
    } catch (error) {
      console.error('❌ Error en login:', error);

      // FORZAR ejecución del MFA setup si hay error 403
      if (error.response?.status === 403) {
        console.log('🚀 FORZANDO MFA SETUP - Error 403 detectado');
        setError('');
        handleMFASetupRequired();
        return;
      }

      setError(error.response?.data?.error || error.message || 'Error al iniciar sesión');
    } finally {
      setLoading(false);
    }
  };

  const handleMFAVerify = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    console.log('🔒 Iniciando verificación MFA...');
    console.log('🔒 User ID:', userId);
    console.log('🔒 MFA Code:', formData.mfaCode);

    try {
      console.log('🔒 Llamando a AuthService.verifyMFA...');
      const response = await AuthService.verifyMFA(userId, formData.mfaCode);
      console.log('🔒 Respuesta MFA exitosa:', response);

      console.log('🔒 Guardando datos de autenticación...');
      AuthService.saveAuthData(response);

      console.log('🔒 Navegando a dashboard...');
      navigate('/dashboard');
    } catch (error) {
      console.error('🔒 Error en verificación MFA:', error);
      console.error('🔒 Error response:', error.response?.data);
      setError(error.response?.data?.error || 'Código MFA inválido');
    } finally {
      setLoading(false);
    }
  };

  const handleMFASetupRequired = async () => {
    console.log('🔧 Iniciando handleMFASetupRequired');
    setLoading(true);
    setError('');

    try {
      console.log('🔧 Paso 1: Obteniendo token temporal...');
      // Obtener token temporal para configurar MFA
      const loginResponse = await AuthService.setupLogin(formData.email, formData.password);
      console.log('🔧 Token temporal obtenido:', loginResponse);
      AuthService.saveAuthData(loginResponse);

      console.log('🔧 Paso 2: Configurando MFA...');
      // Iniciar configuración MFA
      const setupResponse = await AuthService.setupMFA();
      console.log('🔧 MFA setup response:', setupResponse);
      console.log('🔧 QR code data available:', !!setupResponse.qr_code);
      console.log('🔧 QR code length:', setupResponse.qr_code ? setupResponse.qr_code.length : 0);
      setMfaData(setupResponse);
      setStep('mfa-setup');
      console.log('🔧 Paso cambiado a mfa-setup');
    } catch (error) {
      console.error('🔧 Error en handleMFASetupRequired:', error);
      setError(error.response?.data?.error || 'Error al iniciar configuración MFA');
    } finally {
      setLoading(false);
    }
  };

  const handleMFASetupConfirm = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      await AuthService.confirmMFA(formData.mfaCode);
      // MFA configurado exitosamente, ahora hacer login normal
      const response = await AuthService.login(formData.email, formData.password);
      AuthService.saveAuthData(response);
      navigate('/dashboard');
    } catch (error) {
      setError(error.response?.data?.error || 'Código MFA inválido');
    } finally {
      setLoading(false);
    }
  };

  const containerStyle = {
    minHeight: '100vh',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: '#f3f4f6',
    fontFamily: 'Arial, sans-serif'
  };

  const cardStyle = {
    backgroundColor: 'white',
    padding: '2rem',
    borderRadius: '0.5rem',
    boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1)',
    width: '100%',
    maxWidth: '400px'
  };

  const inputStyle = {
    width: '100%',
    padding: '0.75rem',
    border: '1px solid #d1d5db',
    borderRadius: '0.375rem',
    fontSize: '1rem',
    marginBottom: '1rem'
  };

  const buttonStyle = {
    width: '100%',
    padding: '0.75rem',
    backgroundColor: loading ? '#9ca3af' : '#4f46e5',
    color: 'white',
    border: 'none',
    borderRadius: '0.375rem',
    fontSize: '1rem',
    fontWeight: '600',
    cursor: loading ? 'not-allowed' : 'pointer',
    transition: 'background-color 0.2s'
  };

  const errorStyle = {
    color: '#dc2626',
    backgroundColor: '#fef2f2',
    padding: '0.75rem',
    borderRadius: '0.375rem',
    marginBottom: '1rem',
    border: '1px solid #fecaca'
  };

  return (
    <div style={containerStyle}>
      <div style={cardStyle}>
        {/* Header */}
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <h2 style={{ fontSize: '2rem', fontWeight: 'bold', color: '#1f2937', margin: 0 }}>
            🔒 Proyecto Sócrates
          </h2>
          <p style={{ color: '#6b7280', margin: '0.5rem 0 0 0' }}>
            Sistema de Monitoreo SSL/TLS
          </p>
        </div>

        {/* Error message */}
        {error && (
          <div style={errorStyle}>
            {error}
          </div>
        )}

        {/* Login Form */}
        {step === 'login' && (
          <form onSubmit={handleLogin}>
            <div style={{ marginBottom: '1rem' }}>
              <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500' }}>
                Email
              </label>
              <input
                type="email"
                name="email"
                value={formData.email}
                onChange={handleInputChange}
                placeholder="tu@email.com"
                required
                style={inputStyle}
              />
            </div>

            <div style={{ marginBottom: '1.5rem' }}>
              <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500' }}>
                Contraseña
              </label>
              <input
                type="password"
                name="password"
                value={formData.password}
                onChange={handleInputChange}
                placeholder="••••••••"
                required
                style={inputStyle}
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              style={buttonStyle}
              onMouseEnter={(e) => {
                if (!loading) e.target.style.backgroundColor = '#4338ca';
              }}
              onMouseLeave={(e) => {
                if (!loading) e.target.style.backgroundColor = '#4f46e5';
              }}
            >
              {loading ? 'Verificando...' : 'Iniciar Sesión'}
            </button>
          </form>
        )}

        {/* MFA Form */}
        {step === 'mfa' && (
          <form onSubmit={handleMFAVerify}>
            <div style={{ marginBottom: '1rem' }}>
              <h3 style={{ textAlign: 'center', color: '#1f2937' }}>
                Verificación MFA
              </h3>
              <p style={{ textAlign: 'center', color: '#6b7280', fontSize: '0.875rem' }}>
                Ingrese el código de 6 dígitos de su aplicación autenticadora
              </p>
            </div>

            <div style={{ marginBottom: '1.5rem' }}>
              <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500' }}>
                Código MFA
              </label>
              <input
                type="text"
                name="mfaCode"
                value={formData.mfaCode}
                onChange={handleInputChange}
                placeholder="123456"
                maxLength="6"
                required
                style={{
                  ...inputStyle,
                  textAlign: 'center',
                  fontSize: '1.5rem',
                  letterSpacing: '0.5rem'
                }}
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              style={buttonStyle}
            >
              {loading ? 'Verificando...' : 'Verificar Código'}
            </button>

            <button
              type="button"
              onClick={() => {
                setStep('login');
                setFormData({ ...formData, mfaCode: '' });
                setError('');
              }}
              style={{
                ...buttonStyle,
                backgroundColor: 'transparent',
                color: '#6b7280',
                marginTop: '0.5rem',
                fontSize: '0.875rem',
                fontWeight: '400'
              }}
            >
              ← Volver al login
            </button>
          </form>
        )}

        {/* MFA Setup Form */}
        {step === 'mfa-setup' && mfaData && (
          <div>
            <div style={{ marginBottom: '1rem', textAlign: 'center' }}>
              <h3 style={{ color: '#1f2937' }}>
                🔐 Configuración Obligatoria de MFA
              </h3>
              <p style={{ color: '#6b7280', fontSize: '0.875rem' }}>
                Para garantizar la seguridad, todos los usuarios deben configurar autenticación de dos factores
              </p>
            </div>

            <div style={{ marginBottom: '1.5rem', textAlign: 'center' }}>
              <h4 style={{ marginBottom: '1rem', fontSize: '1rem', fontWeight: '500' }}>
                Paso 1: Escanee este código QR
              </h4>
              <img
                src={mfaData.qr_code}
                alt="QR Code para MFA"
                style={{
                  maxWidth: '200px',
                  border: '1px solid #e5e7eb',
                  borderRadius: '0.5rem',
                  display: 'block',
                  margin: '0 auto'
                }}
              />
              <p style={{ fontSize: '0.875rem', color: '#6b7280', marginTop: '0.5rem' }}>
                Use Google Authenticator, Authy u otra app TOTP
              </p>
            </div>

            <form onSubmit={handleMFASetupConfirm}>
              <div style={{ marginBottom: '1.5rem' }}>
                <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500' }}>
                  Paso 2: Ingrese el código de 6 dígitos
                </label>
                <input
                  type="text"
                  name="mfaCode"
                  value={formData.mfaCode}
                  onChange={handleInputChange}
                  placeholder="123456"
                  maxLength="6"
                  required
                  style={{
                    ...inputStyle,
                    textAlign: 'center',
                    fontSize: '1.5rem',
                    letterSpacing: '0.5rem'
                  }}
                />
              </div>

              <button
                type="submit"
                disabled={loading}
                style={buttonStyle}
              >
                {loading ? 'Configurando MFA...' : 'Completar Configuración'}
              </button>
            </form>

            <div style={{
              marginTop: '1rem',
              padding: '1rem',
              backgroundColor: '#fef3c7',
              borderRadius: '0.5rem',
              fontSize: '0.875rem',
              color: '#92400e'
            }}>
              <strong>Código manual:</strong> {mfaData.secret}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Login;