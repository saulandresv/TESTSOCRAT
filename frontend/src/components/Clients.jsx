import React, { useState, useEffect } from 'react';
import Layout from './Layout';
import apiClient from '../services/api';

const Clients = () => {
  const [clients, setClients] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showForm, setShowForm] = useState(false);
  const [editingClient, setEditingClient] = useState(null);
  const [formData, setFormData] = useState({
    name: '',
    status: 'activo'
  });

  useEffect(() => {
    fetchClients();
  }, []);

  const fetchClients = async () => {
    try {
      setLoading(true);
      const response = await apiClient.get('http://localhost:8000/api/clients/');
      setClients(response.data);
    } catch (error) {
      setError('Error al cargar clientes');
      console.error('Error fetching clients:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      if (editingClient) {
        await apiClient.put(`http://localhost:8000/api/clients/${editingClient.id}/`, formData);
      } else {
        await apiClient.post('http://localhost:8000/api/clients/', formData);
      }
      
      setShowForm(false);
      setEditingClient(null);
      setFormData({ name: '', status: 'activo' });
      fetchClients();
    } catch (error) {
      setError('Error al guardar cliente');
      console.error('Error saving client:', error);
    }
  };

  const handleEdit = (client) => {
    setEditingClient(client);
    setFormData({
      name: client.name,
      status: client.status
    });
    setShowForm(true);
  };

  const handleDelete = async (clientId) => {
    if (window.confirm('¿Está seguro de que desea eliminar este cliente?')) {
      try {
        await apiClient.delete(`http://localhost:8000/api/clients/${clientId}/`);
        fetchClients();
      } catch (error) {
        setError('Error al eliminar cliente');
        console.error('Error deleting client:', error);
      }
    }
  };

  const handleInputChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const containerStyle = {
    padding: '2rem',
    maxWidth: '1200px',
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
    maxWidth: '500px',
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
          Cargando clientes...
        </div>
      </div>
    );
  }

  return (
    <Layout>
      <div style={containerStyle}>
      <div style={headerStyle}>
        <h1 style={{ fontSize: '2rem', fontWeight: 'bold', color: '#1f2937' }}>
          🏢 Gestión de Clientes
        </h1>
        <button
          style={buttonStyle}
          onClick={() => {
            setShowForm(true);
            setEditingClient(null);
            setFormData({ name: '', status: 'activo' });
          }}
          onMouseEnter={(e) => e.target.style.backgroundColor = '#4338ca'}
          onMouseLeave={(e) => e.target.style.backgroundColor = '#4f46e5'}
        >
          ➕ Nuevo Cliente
        </button>
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

      <table style={tableStyle}>
        <thead>
          <tr>
            <th style={thStyle}>ID</th>
            <th style={thStyle}>Nombre</th>
            <th style={thStyle}>Estado</th>
            <th style={thStyle}>Fecha Creación</th>
            <th style={thStyle}>Acciones</th>
          </tr>
        </thead>
        <tbody>
          {clients.map((client) => (
            <tr key={client.id} style={{ '&:hover': { backgroundColor: '#f8fafc' } }}>
              <td style={tdStyle}>{client.id}</td>
              <td style={tdStyle}>{client.name}</td>
              <td style={tdStyle}>
                <span style={{
                  padding: '0.25rem 0.75rem',
                  borderRadius: '9999px',
                  fontSize: '0.875rem',
                  fontWeight: '500',
                  backgroundColor: client.status === 'activo' ? '#d1fae5' : '#fee2e2',
                  color: client.status === 'activo' ? '#065f46' : '#dc2626'
                }}>
                  {client.status === 'activo' ? '✅ Activo' : '❌ Inactivo'}
                </span>
              </td>
              <td style={tdStyle}>
                {new Date(client.created_at).toLocaleDateString('es-CL')}
              </td>
              <td style={tdStyle}>
                <button
                  onClick={() => handleEdit(client)}
                  style={{
                    ...buttonStyle,
                    backgroundColor: '#059669',
                    marginRight: '0.5rem',
                    padding: '0.5rem 1rem',
                    fontSize: '0.875rem'
                  }}
                >
                  ✏️ Editar
                </button>
                <button
                  onClick={() => handleDelete(client.id)}
                  style={{
                    ...buttonStyle,
                    backgroundColor: '#dc2626',
                    padding: '0.5rem 1rem',
                    fontSize: '0.875rem'
                  }}
                >
                  🗑️ Eliminar
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {clients.length === 0 && (
        <div style={{
          textAlign: 'center',
          padding: '3rem',
          backgroundColor: 'white',
          borderRadius: '0.5rem',
          marginTop: '1rem'
        }}>
          <h3>No hay clientes registrados</h3>
          <p style={{ color: '#6b7280', marginBottom: '1rem' }}>
            Crea tu primer cliente para comenzar a monitorear certificados SSL/TLS
          </p>
          <button
            style={buttonStyle}
            onClick={() => setShowForm(true)}
          >
            ➕ Crear Primer Cliente
          </button>
        </div>
      )}

      {/* Modal del formulario */}
      {showForm && (
        <div style={modalStyle} onClick={(e) => {
          if (e.target === e.currentTarget) {
            setShowForm(false);
            setEditingClient(null);
          }
        }}>
          <div style={formStyle}>
            <h2 style={{ marginBottom: '1.5rem', fontSize: '1.5rem', fontWeight: 'bold' }}>
              {editingClient ? 'Editar Cliente' : 'Nuevo Cliente'}
            </h2>
            
            <form onSubmit={handleSubmit}>
              <div>
                <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500' }}>
                  Nombre del Cliente *
                </label>
                <input
                  type="text"
                  name="name"
                  value={formData.name}
                  onChange={handleInputChange}
                  required
                  placeholder="Ej: Empresa ABC S.A."
                  style={inputStyle}
                />
              </div>

              <div>
                <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: '500' }}>
                  Estado
                </label>
                <select
                  name="status"
                  value={formData.status}
                  onChange={handleInputChange}
                  style={inputStyle}
                >
                  <option value="activo">Activo</option>
                  <option value="inactivo">Inactivo</option>
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
                  {editingClient ? '💾 Actualizar' : '➕ Crear Cliente'}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setShowForm(false);
                    setEditingClient(null);
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

export default Clients;