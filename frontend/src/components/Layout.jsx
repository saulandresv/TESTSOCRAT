import React from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { AuthService } from '../services/auth';

const Layout = ({ children }) => {
  const location = useLocation();
  const navigate = useNavigate();
  const user = AuthService.getCurrentUser();

  const handleLogout = () => {
    AuthService.logout();
    navigate('/login');
  };

  const navigation = [
    { name: 'Dashboard', href: '/dashboard', icon: '📊' },
    { name: 'Certificados', href: '/certificates', icon: '🔒' },
    { name: 'Análisis', href: '/analysis', icon: '🔍' },
    { name: 'Reportes', href: '/reports', icon: '📄' },
  ];

  // Navegación adicional para ADMIN
  const adminNavigation = [
    { name: 'Usuarios', href: '/users', icon: '👥' },
    { name: 'Clientes', href: '/clients', icon: '🏢' },
  ];

  return (
    <div style={{ display: 'flex', height: '100vh', fontFamily: 'Arial, sans-serif' }}>
      {/* Sidebar */}
      <div style={{
        width: '250px',
        backgroundColor: '#1f2937',
        color: 'white',
        padding: '1rem',
        display: 'flex',
        flexDirection: 'column'
      }}>
        {/* Logo */}
        <div style={{ marginBottom: '2rem' }}>
          <h2 style={{ margin: 0, fontSize: '1.5rem' }}>🔒 Sócrates</h2>
          <p style={{ margin: '0.5rem 0 0 0', fontSize: '0.875rem', opacity: 0.7 }}>
            SSL Monitor
          </p>
        </div>

        {/* Usuario */}
        <Link 
          to="/profile"
          style={{
            display: 'block',
            padding: '1rem',
            backgroundColor: '#374151',
            borderRadius: '0.5rem',
            marginBottom: '2rem',
            textDecoration: 'none',
            color: 'white',
            transition: 'background-color 0.2s'
          }}
          onMouseEnter={(e) => e.target.style.backgroundColor = '#4b5563'}
          onMouseLeave={(e) => e.target.style.backgroundColor = '#374151'}
        >
          <div style={{ fontSize: '0.875rem', fontWeight: 'bold' }}>
            {user?.email}
          </div>
          <div style={{ fontSize: '0.75rem', opacity: 0.7 }}>
            {user?.rol} • Ver perfil
          </div>
        </Link>

        {/* Navegación principal */}
        <nav style={{ flex: 1 }}>
          <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
            {navigation.map((item) => (
              <li key={item.name} style={{ marginBottom: '0.5rem' }}>
                <Link
                  to={item.href}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    padding: '0.75rem',
                    borderRadius: '0.375rem',
                    textDecoration: 'none',
                    color: 'white',
                    backgroundColor: location.pathname === item.href ? '#4f46e5' : 'transparent',
                    transition: 'background-color 0.2s',
                  }}
                  onMouseEnter={(e) => {
                    if (location.pathname !== item.href) {
                      e.target.style.backgroundColor = '#374151';
                    }
                  }}
                  onMouseLeave={(e) => {
                    if (location.pathname !== item.href) {
                      e.target.style.backgroundColor = 'transparent';
                    }
                  }}
                >
                  <span style={{ marginRight: '0.75rem', fontSize: '1.2rem' }}>
                    {item.icon}
                  </span>
                  {item.name}
                </Link>
              </li>
            ))}
            
            {/* Navegación de admin */}
            {AuthService.isAdmin() && (
              <>
                <hr style={{ margin: '1rem 0', border: '1px solid #374151' }} />
                {adminNavigation.map((item) => (
                  <li key={item.name} style={{ marginBottom: '0.5rem' }}>
                    <Link
                      to={item.href}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        padding: '0.75rem',
                        borderRadius: '0.375rem',
                        textDecoration: 'none',
                        color: 'white',
                        backgroundColor: location.pathname === item.href ? '#4f46e5' : 'transparent',
                        transition: 'background-color 0.2s',
                      }}
                    >
                      <span style={{ marginRight: '0.75rem', fontSize: '1.2rem' }}>
                        {item.icon}
                      </span>
                      {item.name}
                    </Link>
                  </li>
                ))}
              </>
            )}
          </ul>
        </nav>

        {/* Logout */}
        <button
          onClick={handleLogout}
          style={{
            width: '100%',
            padding: '0.75rem',
            backgroundColor: '#dc2626',
            color: 'white',
            border: 'none',
            borderRadius: '0.375rem',
            cursor: 'pointer',
            fontSize: '0.875rem',
            fontWeight: '500',
            transition: 'background-color 0.2s'
          }}
          onMouseEnter={(e) => e.target.style.backgroundColor = '#b91c1c'}
          onMouseLeave={(e) => e.target.style.backgroundColor = '#dc2626'}
        >
          🚪 Cerrar Sesión
        </button>
      </div>

      {/* Contenido principal */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
        {/* Header */}
        <header style={{
          backgroundColor: 'white',
          borderBottom: '1px solid #e5e7eb',
          padding: '1rem 2rem',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <h1 style={{ margin: 0, fontSize: '1.5rem', color: '#1f2937' }}>
            Sistema de Monitoreo SSL/TLS
          </h1>
          <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>
            {new Date().toLocaleDateString('es-CL')}
          </div>
        </header>

        {/* Contenido */}
        <main style={{
          flex: 1,
          padding: '2rem',
          backgroundColor: '#f9fafb',
          overflow: 'auto'
        }}>
          {children}
        </main>
      </div>
    </div>
  );
};

export default Layout;