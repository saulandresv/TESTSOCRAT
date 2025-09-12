import React, { useState, useEffect } from 'react';
import Layout from './Layout';
import apiClient from '../services/api';
import { AuthService } from '../services/auth';

const Users = () => {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showForm, setShowForm] = useState(false);
  const [editingUser, setEditingUser] = useState(null);
  const [formData, setFormData] = useState({
    email: '',
    nombre_usuario: '',
    password: '',
    rol: 'CLIENTE',
    estado: 'activo'
  });

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    try {
      setLoading(true);
      const response = await apiClient.get('http://localhost:8000/api/v1/users/');
      setUsers(response.data);
    } catch (error) {
      setError('Error al cargar usuarios');
      console.error('Error fetching users:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      if (editingUser) {
        // Para editar, no enviamos password si está vacío
        const updateData = { ...formData };
        if (!updateData.password) {
          delete updateData.password;
        }
        await apiClient.put(`http://localhost:8000/api/v1/users/${editingUser.id}/`, updateData);
      } else {
        await apiClient.post('http://localhost:8000/api/v1/users/', formData);
      }
      
      setShowForm(false);
      setEditingUser(null);
      setFormData({
        email: '',
        nombre_usuario: '',
        password: '',
        rol: 'CLIENTE',
        estado: 'activo'
      });
      fetchUsers();
    } catch (error) {
      setError('Error al guardar usuario');
      console.error('Error saving user:', error);
    }
  };

  const handleEdit = (user) => {
    setEditingUser(user);
    setFormData({
      email: user.email,
      nombre_usuario: user.nombre_usuario,
      password: '', // No mostramos la contraseña actual
      rol: user.rol,
      estado: user.estado
    });
    setShowForm(true);
  };

  const handleToggleStatus = async (userId) => {
    try {
      await apiClient.post(`http://localhost:8000/api/v1/users/${userId}/toggle_status/`);
      fetchUsers();
    } catch (error) {
      setError('Error al cambiar estado del usuario');
      console.error('Error toggling user status:', error);
    }
  };

  const handleInputChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const getRoleBadge = (rol) => {
    const colors = {
      'ADMIN': { bg: '#dbeafe', color: '#1e40af' },
      'ANALISTA': { bg: '#d1fae5', color: '#065f46' },
      'CLIENTE': { bg: '#fef3c7', color: '#92400e' }
    };
    const color = colors[rol] || colors['CLIENTE'];
    
    return {
      padding: '0.25rem 0.75rem',
      borderRadius: '9999px',
      fontSize: '0.875rem',
      fontWeight: '500',
      backgroundColor: color.bg,
      color: color.color
    };
  };

  const currentUser = AuthService.getCurrentUser();

  const containerStyle = {
    padding: '2rem',
    maxWidth: '1400px',
    margin: '0 auto',
    fontFamily: 'Arial, sans-serif'
  };

  const headerStyle = {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '2rem'
  };

  const buttonStyle = {
    padding: '0.75rem 1.5rem',
    backgroundColor: '#4f46e5',
    color: 'white',
    border: 'none',
    borderRadius: '0.375rem',
    cursor: 'pointer',
    fontSize: '1rem',
    fontWeight: '500'
  };

  const tableStyle = {
    width: '100%',
    borderCollapse: 'collapse',
    backgroundColor: 'white',
    borderRadius: '0.5rem',
    overflow: 'hidden',
    boxShadow: '0 1px 3px rgba(0, 0, 0, 0.1)'
  };

  const thStyle = {
    backgroundColor: '#f8fafc',
    padding: '1rem',
    textAlign: 'left',
    fontWeight: '600',
    borderBottom: '1px solid #e2e8f0'
  };

  const tdStyle = {
    padding: '1rem',
    borderBottom: '1px solid #e2e8f0'
  };

  const modalStyle = {
    position: 'fixed',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    backgroundColor: 'rgba(0, 0, 0, 0.5)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 1000
  };

  const formStyle = {
    backgroundColor: 'white',
    padding: '2rem',
    borderRadius: '0.5rem',
    width: '100%',
    maxWidth: '600px',
    margin: '1rem'
  };

  const inputStyle = {
    width: '100%',
    padding: '0.75rem',
    border: '1px solid #d1d5db',
    borderRadius: '0.375rem',
    fontSize: '1rem',
    marginBottom: '1rem'
  };

  if (loading) {
    return (
      <div style={containerStyle}>
        <div style={{ textAlign: 'center', padding: '2rem' }}>
          Cargando usuarios...
        </div>
      </div>
    );
  }

  return (
    <Layout>
      <div style={containerStyle}>
      <div style={headerStyle}>
        <h1 style={{ fontSize: '2rem', fontWeight: 'bold', color: '#1f2937' }}>
          👤 Gestión de Usuarios
        </h1>
        {currentUser?.rol === 'ADMIN' && (
          <button
            style={buttonStyle}
            onClick={() => {
              setShowForm(true);
              setEditingUser(null);
              setFormData({
                email: '',
                nombre_usuario: '',
                password: '',
                rol: 'CLIENTE',
                estado: 'activo'
              });
            }}
            onMouseEnter={(e) => e.target.style.backgroundColor = '#4338ca'}
            onMouseLeave={(e) => e.target.style.backgroundColor = '#4f46e5'}
          >
            ➕ Nuevo Usuario
          </button>
        )}
      </div>

      {error && (
        <div style={{
          backgroundColor: '#fee2e2',
          color: '#dc2626',
          padding: '1rem',
          borderRadius: '0.375rem',
          marginBottom: '1rem',
          border: '1px solid #fecaca'
        }}>
          {error}
        </div>
      )}

      <div style={{ overflowX: 'auto' }}>
        <table style={tableStyle}>
          <thead>
            <tr>
              <th style={thStyle}>ID</th>
              <th style={thStyle}>Email</th>
              <th style={thStyle}>Nombre</th>
              <th style={thStyle}>Rol</th>
              <th style={thStyle}>Estado</th>
              <th style={thStyle}>MFA</th>
              <th style={thStyle}>Último Login</th>
              <th style={thStyle}>Registro</th>
              {currentUser?.rol === 'ADMIN' && <th style={thStyle}>Acciones</th>}
            </tr>
          </thead>
          <tbody>
            {users.map((user) => (
              <tr key={user.id}>
                <td style={tdStyle}>{user.id}</td>
                <td style={tdStyle}>{user.email}</td>
                <td style={tdStyle}>{user.nombre_usuario}</td>
                <td style={tdStyle}>
                  <span style={getRoleBadge(user.rol)}>
                    {user.rol === 'ADMIN' ? '👑 Admin' : 
                     user.rol === 'ANALISTA' ? '🔍 Analista' : '👤 Cliente'}
                  </span>
                </td>
                <td style={tdStyle}>
                  <span style={{
                    padding: '0.25rem 0.75rem',
                    borderRadius: '9999px',
                    fontSize: '0.875rem',
                    fontWeight: '500',
                    backgroundColor: user.estado === 'activo' ? '#d1fae5' : '#fee2e2',
                    color: user.estado === 'activo' ? '#065f46' : '#dc2626'
                  }}>
                    {user.estado === 'activo' ? '✅ Activo' : '❌ Inactivo'}
                  </span>
                </td>
                <td style={tdStyle}>
                  {user.mfa_enabled ? '🔐 Habilitado' : '🔓 Deshabilitado'}
                </td>
                <td style={tdStyle}>
                  {user.ultimo_login ? 
                    new Date(user.ultimo_login).toLocaleDateString('es-CL') : 
                    'Nunca'
                  }
                </td>
                <td style={tdStyle}>
                  {new Date(user.date_joined).toLocaleDateString('es-CL')}
                </td>
                {currentUser?.rol === 'ADMIN' && (
                  <td style={tdStyle}>
                    <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                      <button
                        onClick={() => handleEdit(user)}
                        style={{
                          ...buttonStyle,
                          backgroundColor: '#059669',
                          padding: '0.5rem 1rem',
                          fontSize: '0.875rem'
                        }}
                      >
                        ✏️ Editar
                      </button>
                      {user.id !== currentUser?.id && (
                        <button
                          onClick={() => handleToggleStatus(user.id)}
                          style={{
                            ...buttonStyle,
                            backgroundColor: user.estado === 'activo' ? '#dc2626' : '#059669',
                            padding: '0.5rem 1rem',
                            fontSize: '0.875rem'
                          }}
                        >
                          {user.estado === 'activo' ? '❌ Desactivar' : '✅ Activar'}
                        </button>
                      )}
                    </div>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {users.length === 0 && (
        <div style={{
          textAlign: 'center',
          padding: '3rem',
          backgroundColor: 'white',
          borderRadius: '0.5rem',
          marginTop: '1rem'
        }}>
          <h3>No hay usuarios registrados</h3>
          <p style={{ color: '#6b7280' }}>
            Los usuarios se mostrarán aquí una vez creados
          </p>
        </div>
      )}

      {/* Modal del formulario */}
      {showForm && currentUser?.rol === 'ADMIN' && (
        <div style={modalStyle} onClick={(e) => {
          if (e.target === e.currentTarget) {
            setShowForm(false);
            setEditingUser(null);
          }
        }}>
          <div style={formStyle}>
            <h2 style={{ marginBottom: '1.5rem', fontSize: '1.5rem', fontWeight: 'bold' }}>
              {editingUser ? 'Editar Usuario' : 'Nuevo Usuario'}
            </h2>
            
            <form onSubmit={handleSubmit}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                <div>
                  <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500' }}>
                    Email *
                  </label>
                  <input
                    type="email"
                    name="email"
                    value={formData.email}
                    onChange={handleInputChange}
                    required
                    placeholder="usuario@empresa.com"
                    style={inputStyle}
                  />
                </div>

                <div>
                  <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500' }}>
                    Nombre de Usuario *
                  </label>
                  <input
                    type="text"
                    name="nombre_usuario"
                    value={formData.nombre_usuario}
                    onChange={handleInputChange}
                    required
                    placeholder="Juan Pérez"
                    style={inputStyle}
                  />
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                <div>
                  <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500' }}>
                    {editingUser ? 'Nueva Contraseña (opcional)' : 'Contraseña *'}
                  </label>
                  <input
                    type="password"
                    name="password"
                    value={formData.password}
                    onChange={handleInputChange}
                    required={!editingUser}
                    placeholder={editingUser ? 'Dejar vacío para no cambiar' : 'Mínimo 8 caracteres'}
                    style={inputStyle}
                  />
                </div>

                <div>
                  <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500' }}>
                    Rol
                  </label>
                  <select
                    name="rol"
                    value={formData.rol}
                    onChange={handleInputChange}
                    style={inputStyle}
                  >
                    <option value="CLIENTE">👤 Cliente</option>
                    <option value="ANALISTA">🔍 Analista</option>
                    <option value="ADMIN">👑 Administrador</option>
                  </select>
                </div>
              </div>

              <div>
                <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500' }}>
                  Estado
                </label>
                <select
                  name="estado"
                  value={formData.estado}
                  onChange={handleInputChange}
                  style={inputStyle}
                >
                  <option value="activo">✅ Activo</option>
                  <option value="inactivo">❌ Inactivo</option>
                </select>
              </div>

              <div style={{ display: 'flex', gap: '1rem', marginTop: '1.5rem' }}>
                <button
                  type="submit"
                  style={{
                    ...buttonStyle,
                    flex: 1
                  }}
                >
                  {editingUser ? '💾 Actualizar' : '➕ Crear Usuario'}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setShowForm(false);
                    setEditingUser(null);
                  }}
                  style={{
                    ...buttonStyle,
                    backgroundColor: '#6b7280',
                    flex: 1
                  }}
                >
                  ❌ Cancelar
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

export default Users;