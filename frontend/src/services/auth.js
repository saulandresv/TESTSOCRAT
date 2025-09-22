import apiClient from './api';

export class AuthService {
  /**
   * Login inicial (email + password)
   */
  static async login(email, password) {
    const response = await apiClient.post('/auth/login/', {
      email,
      password,
    });
    return response.data;
  }

  /**
   * Verificar MFA
   */
  static async verifyMFA(userId, mfaCode) {
    console.log('🔐 AuthService.verifyMFA called with:', { userId, mfaCode });

    try {
      const response = await apiClient.post('/auth/mfa/verify/', {
        user_id: userId,
        mfa_code: mfaCode,
      });
      console.log('🔐 MFA verification response:', response.data);
      return response.data;
    } catch (error) {
      console.error('🔐 MFA verification error:', error);
      console.error('🔐 Error response data:', error.response?.data);
      throw error;
    }
  }

  /**
   * Login temporal para configurar MFA
   */
  static async setupLogin(email, password) {
    const response = await apiClient.post('/auth/mfa/setup-login/', {
      email,
      password,
    });
    return response.data;
  }

  /**
   * Configurar MFA (solo requiere autenticación)
   */
  static async setupMFA() {
    console.log('🔐 AuthService.setupMFA called');
    try {
      const response = await apiClient.post('/auth/mfa/setup/', {});
      console.log('🔐 MFA setup response:', response.data);
      console.log('🔐 QR code present:', !!response.data.qr_code);
      return response.data;
    } catch (error) {
      console.error('🔐 MFA setup error:', error);
      throw error;
    }
  }

  /**
   * Confirmar y habilitar MFA con código TOTP
   */
  static async confirmMFA(mfaCode) {
    const response = await apiClient.put('/auth/mfa/setup/', {
      mfa_code: mfaCode,
    });
    return response.data;
  }

  /**
   * Deshabilitar MFA
   */
  static async disableMFA(password, token) {
    const response = await apiClient.delete('/auth/mfa/setup/', {
      data: { password, token }
    });
    return response.data;
  }

  /**
   * Obtener perfil del usuario
   */
  static async getProfile() {
    const response = await apiClient.get('/auth/profile/');
    return response.data;
  }

  /**
   * Refresh token
   */
  static async refreshToken() {
    const refreshToken = localStorage.getItem('refresh_token');
    const response = await apiClient.post('/auth/refresh/', {
      refresh: refreshToken,
    });
    return response.data;
  }

  /**
   * Logout
   */
  static logout() {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('user');
    window.location.href = '/login';
  }

  /**
   * Verificar si el usuario está autenticado
   */
  static isAuthenticated() {
    const token = localStorage.getItem('access_token');
    const user = localStorage.getItem('user');
    return !!(token && user);
  }

  /**
   * Obtener usuario actual
   */
  static getCurrentUser() {
    const userStr = localStorage.getItem('user');
    return userStr ? JSON.parse(userStr) : null;
  }

  /**
   * Guardar datos de autenticación
   */
  static saveAuthData(data) {
    if (data.access) localStorage.setItem('access_token', data.access);
    if (data.refresh) localStorage.setItem('refresh_token', data.refresh);
    if (data.user) localStorage.setItem('user', JSON.stringify(data.user));
  }

  /**
   * Verificar si es administrador
   */
  static isAdmin() {
    const user = this.getCurrentUser();
    return user?.rol === 'ADMIN';
  }

  /**
   * Verificar si es analista
   */
  static isAnalyst() {
    const user = this.getCurrentUser();
    return user?.rol === 'ANALISTA';
  }
}

export default AuthService;