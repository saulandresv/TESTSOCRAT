# 🔒 Proyecto Sócrates - Guía de Uso Completa

## Sistema de Monitoreo SSL/TLS

¡Bienvenido al sistema de monitoreo de certificados SSL/TLS más completo! Esta guía te ayudará a utilizar todas las funcionalidades disponibles.

---

## 🚀 Inicio Rápido

### 1. Preparar el Sistema

```bash
# Backend - Instalar dependencias y configurar base de datos
cd backend
python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate
pip install -r requirements.txt

# Configurar base de datos
python manage.py migrate

# Crear superusuario
python manage.py createsuperuser

# Poblar con datos de ejemplo
python manage.py seed_certificates --count 15
```

```bash
# Frontend - Instalar dependencias React
cd frontend
npm install
npm start
```

### 2. Docker (Recomendado)

```bash
# Levantar todo el sistema
docker-compose up --build

# El sistema estará disponible en:
# - Frontend: http://localhost:3000
# - Backend: http://localhost:8000
# - MySQL: puerto 3306
# - Redis: puerto 6379
```

---

## 📋 Funcionalidades Principales

### 🏠 Dashboard Principal
- **Vista general** del estado de todos los certificados
- **Estadísticas en tiempo real** con gráficos interactivos
- **Alertas automáticas** para vulnerabilidades críticas
- **Puntuaciones de seguridad** con visualización circular
- **Tendencias** de análisis y certificados

### 🔒 Gestión de Certificados
- **Agregar certificados** por URL o IP
- **Protocolos soportados**: HTTPS, TLS, SSH, SMTP, IMAP, POP3
- **Monitoreo automático** de vitalidad
- **Seguimiento de expiración** con alertas tempranas
- **Filtros avanzados** por cliente, protocolo, estado

### 🔍 Análisis SSL Avanzado
- **Motor de análisis integrado** con múltiples herramientas:
  - **nmap**: Enumeración de cifrados y certificados
  - **openssl**: Análisis de protocolos TLS/SSL
  - **sslscan**: Análisis completo con XML parsing
  - **sslyze**: Análisis avanzado con Python API

### 📊 Visualización de Resultados
- **Puntuación de seguridad** con escala A-F
- **Matriz de protocolos** soportados
- **Gráfico de vulnerabilidades** por severidad
- **Detalles de cifrados** fuertes vs débiles
- **Timeline de análisis** históricos

### 👥 Gestión de Clientes
- **Organización por cliente** empresarial
- **Múltiples certificados** por cliente
- **Informes personalizados** por organización

---

## 🎯 Casos de Uso Comunes

### Caso 1: Monitorear Sitio Web Corporativo

1. **Ir a "Certificados"** en el menú
2. **Hacer clic en "Nuevo Certificado"**
3. **Configurar**:
   - **Tipo**: URL/Dominio
   - **URL**: `tudominio.com`
   - **Puerto**: `443`
   - **Protocolo**: `HTTPS`
   - **Cliente**: Seleccionar o crear
   - **Frecuencia**: `30 días`

4. **Hacer clic en "Crear y Analizar"**

### Caso 2: Análisis de Servidor SSH

1. **Agregar certificado SSH**:
   - **Tipo**: IP o URL
   - **Puerto**: `22`
   - **Protocolo**: `SSH`

2. **Ejecutar análisis manual** desde la lista
3. **Revisar vulnerabilidades** SSH específicas

### Caso 3: Auditoría de Múltiples Servicios

1. **Usar el seeder** para datos de prueba:
   ```bash
   python manage.py seed_certificates --count 20
   ```

2. **Seleccionar múltiples certificados** en la lista
3. **Ejecutar "Análisis en lote"**
4. **Revisar resultados** en la sección "Análisis"

---

## 🔧 Configuración Avanzada

### Variables de Entorno

```env
# Backend (.env)
DEBUG=True
SECRET_KEY=tu-clave-secreta
DATABASE_URL=mysql://usuario:password@localhost/socrates
REDIS_URL=redis://localhost:6379/0

# Configuración de análisis
SSL_ANALYSIS_TIMEOUT=30
MAX_CONCURRENT_ANALYSES=5
ANALYSIS_RETENTION_DAYS=90
```

### Configuración de Celery (Análisis Automáticos)

```bash
# Iniciar worker de Celery
celery -A config worker -l info

# Iniciar scheduler para tareas programadas
celery -A config beat -l info
```

### Personalizar Herramientas de Análisis

Edita `backend/analysis/external_tools.py` para:
- **Añadir nuevas herramientas** de análisis
- **Modificar timeouts** y configuraciones
- **Personalizar detección** de vulnerabilidades

---

## 📈 Interpretación de Resultados

### Puntuaciones de Seguridad

- **90-100 (A)**: 🟢 Excelente - Configuración muy segura
- **80-89 (B)**: 🟡 Buena - Configuración segura con mejoras menores
- **70-79 (C)**: 🟠 Aceptable - Requiere algunas mejoras
- **60-69 (D)**: 🔴 Deficiente - Varios problemas de seguridad
- **0-59 (F)**: ⚫ Crítico - Problemas graves de seguridad

### Severidad de Vulnerabilidades

- **🚨 CRITICAL**: Requiere atención **inmediata**
- **⚠️ HIGH**: Corregir en **1-7 días**
- **🟡 MEDIUM**: Corregir en **1-30 días**
- **🟢 LOW**: Monitorear y corregir cuando sea posible

### Estados de Certificados

- **🟢 UP/Activo**: Certificado accesible y válido
- **🔴 DOWN/Inactivo**: No se puede conectar o certificado inválido
- **⏰ Por Expirar**: Menos de 30 días para vencer
- **❌ Expirado**: Certificado vencido

---

## 🛠️ Mantenimiento

### Limpieza de Datos

```bash
# Limpiar análisis antiguos (90+ días)
python manage.py cleanup_old_analyses

# Regenerar certificados de ejemplo
python manage.py seed_certificates --clean --count 10
```

### Backup de Base de Datos

```bash
# MySQL
mysqldump -u root -p socrates > backup_$(date +%Y%m%d).sql

# Restaurar
mysql -u root -p socrates < backup_20241201.sql
```

### Monitoreo del Sistema

- **Logs de Django**: `backend/logs/django.log`
- **Logs de Celery**: Revisar worker output
- **Métricas de Redis**: `redis-cli info`

---

## 🔍 Resolución de Problemas

### Problemas Comunes

**❌ Error: "sslscan command not found"**
```bash
# Ubuntu/Debian
sudo apt install sslscan

# macOS
brew install sslscan
```

**❌ Error: "sslyze module not found"**
```bash
pip install sslyze==5.2.0
```

**❌ Análisis se queda "En Progreso"**
- Verificar que Celery worker esté corriendo
- Revisar logs de Celery para errores
- Aumentar timeout en configuración

**❌ Frontend no se conecta al backend**
- Verificar que el backend esté en puerto 8000
- Revisar CORS en `settings.py`
- Verificar configuración de proxy en React

### Debugging Avanzado

```bash
# Ver logs en tiempo real
tail -f backend/logs/django.log

# Inspeccionar tareas de Celery
celery -A config inspect active

# Test de conectividad SSL manual
openssl s_client -connect google.com:443 -brief
```

---

## 🎨 Personalización

### Temas y Colores

Modifica `frontend/src/components/` para cambiar:
- **Colores de severidad** en `Analysis.jsx`
- **Esquemas de color** en `Dashboard.jsx`
- **Iconos y emojis** en todos los componentes

### Nuevos Tipos de Análisis

1. **Crear nuevo analizador** en `backend/analysis/analyzers/`
2. **Añadir al motor** en `analysis_engine.py`
3. **Actualizar frontend** para mostrar nuevos resultados

---

## 📞 Soporte y Contribución

### Reportar Problemas

1. **Recopilar información**:
   - Versión del sistema operativo
   - Logs de error específicos
   - Pasos para reproducir el problema

2. **Incluir contexto**:
   - Configuración de certificados
   - Tipo de análisis que falla
   - Herramientas de sistema disponibles

### Contribuir

1. **Fork del repositorio**
2. **Crear rama para feature**: `git checkout -b feature/nueva-funcionalidad`
3. **Commit cambios**: `git commit -am 'Añadir nueva funcionalidad'`
4. **Push a la rama**: `git push origin feature/nueva-funcionalidad`
5. **Crear Pull Request**

---

## 🏆 ¡Sistema Completo y Listo!

El Proyecto Sócrates ahora incluye:

✅ **Backend completo** con Django + DRF  
✅ **Frontend React** con interfaz moderna  
✅ **Motor de análisis SSL** con 4+ herramientas  
✅ **Sistema de autenticación** con MFA  
✅ **Dashboard interactivo** con métricas  
✅ **Análisis automatizados** con Celery  
✅ **Base de datos** con 11 modelos  
✅ **Containerización** Docker completa  
✅ **Seeder de datos** para testing  
✅ **Documentación completa**  

¡Disfruta monitoreando tus certificados SSL con la máxima seguridad! 🔒✨