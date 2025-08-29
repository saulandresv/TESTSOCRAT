import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { AuthService } from '../services/auth';

const Login = () => {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    mfaCode: ''
  });
  const [step, setStep] = useState('login'); // 'login' | 'mfa'
  const [userId, setUserId] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
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
      const response = await AuthService.login(formData.email, formData.password);

      if (response.mfa_required) {
        // Requiere MFA
        setStep('mfa');
        setUserId(response.user_id);
      } else {
        // Login exitoso sin MFA
        AuthService.saveAuthData(response);
        navigate('/dashboard');
      }
    } catch (error) {
      setError(error.response?.data?.error || 'Error al iniciar sesión');
    } finally {
      setLoading(false);
    }
  };

  const handleMFAVerify = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await AuthService.verifyMFA(userId, formData.mfaCode);
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
      </div>
    </div>
  );
};

export default Login;