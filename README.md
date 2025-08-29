# 🔒 Proyecto Sócrates - Sistema de Monitoreo SSL/TLS

Sistema completo de vigilancia activa sobre certificados digitales con análisis automatizado, monitoreo de vitalidad y generación de reportes.

## 🚀 Características Principales

### ✅ Sistema de Autenticación Avanzado
- **Autenticación Multi-Factor (MFA)** con códigos TOTP
- Roles de usuario: ADMIN, ANALISTA, CLIENTE
- JWT con refresh tokens automático
- Control de acceso granular por cliente

### 🔍 Análisis SSL/TLS Completo
- **Motor de análisis integrado** con nmap, openssl, sslyze
- Detección de vulnerabilidades críticas (Heartbleed, POODLE, DROWN)
- Evaluación de protocolos TLS, cifrados y Perfect Forward Secrecy
- Validación de cadenas de certificación completas
- Análisis de headers de seguridad web (HSTS, OCSP Stapling)

### 📊 Monitoreo Automatizado
- **Verificación de vitalidad** cada 5 minutos
- Análisis programados con Celery Beat
- Alertas automáticas por expiración de certificados
- Dashboard con estadísticas en tiempo real

### 📄 Sistema de Reportes
- Generación de reportes PDF/Excel/JSON
- Filtros avanzados por cliente, protocolo, fechas
- Reportes detallados y resumidos
- Descarga automática de archivos generados

## 🏗️ Arquitectura Técnica

### Backend (Django + DRF)
- **Framework**: Django 5.0 + Django REST Framework
- **Base de datos**: MySQL con 11 tablas especializadas
- **Autenticación**: JWT + MFA con pyotp
- **Tareas asíncronas**: Celery + Redis
- **APIs**: OpenAPI/Swagger documentadas

### Frontend (React + Vite)
- **Framework**: React 18 con Vite
- **Routing**: React Router con rutas protegidas
- **HTTP Client**: Axios con interceptores
- **UI**: Componentes funcionales con hooks

### Infraestructura
- **Contenedores**: Docker Compose
- **Cache/Queue**: Redis
- **Monitoreo**: Celery Beat scheduler
- **Archivos**: Sistema de media files

## 📋 Requisitos del Sistema

- Python 3.12+
- Node.js 18+
- MySQL 8.0+
- Redis 6.0+
- Docker & Docker Compose (opcional)

## 🚀 Instalación y Configuración

### 1. Clonar y configurar el proyecto

```bash
# Clonar repositorio
git clone <repository-url>
cd Proyecto-Socrates

# Configurar variables de entorno
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env
```

### 2. Configuración del Backend

```bash
cd backend

# Crear entorno virtual
python3 -m venv .venv
source .venv/bin/activate  # Linux/Mac
# o .venv\Scripts\activate  # Windows

# Instalar dependencias
pip install -r requirements.txt

# Configurar base de datos
python manage.py makemigrations
python manage.py migrate

# Crear superusuario
python manage.py createsuperuser

# Cargar datos iniciales (opcional)
python manage.py loaddata fixtures/initial_data.json
```

### 3. Configuración del Frontend

```bash
cd frontend

# Instalar dependencias
npm install

# Configurar variables de entorno
echo "VITE_API_BASE_URL=http://localhost:8000/api/v1" > .env
```

### 4. Ejecutar el Sistema

#### Opción A: Con Docker (Recomendado)

```bash
# Desde la raíz del proyecto
docker-compose up -d

# El sistema estará disponible en:
# - Frontend: http://localhost:3000
# - Backend: http://localhost:8000
# - API Docs: http://localhost:8000/api/schema/swagger/
```

#### Opción B: Manual

```bash
# Terminal 1: Backend
cd backend
source .venv/bin/activate
python manage.py runserver 8000

# Terminal 2: Frontend  
cd frontend
npm run dev

# Terminal 3: Celery Worker
cd backend
source .venv/bin/activate
celery -A config worker -l info

# Terminal 4: Celery Beat
cd backend
source .venv/bin/activate
celery -A config beat -l info
```

## 🔧 Configuración Avanzada

### Variables de Entorno del Backend

```env
# Base de datos
MYSQL_HOST=localhost
MYSQL_DATABASE=socrates
MYSQL_USER=socrates
MYSQL_PASSWORD=your_password

# Seguridad
SECRET_KEY=your-secret-key
DEBUG=False
ALLOWED_HOSTS=localhost,127.0.0.1

# JWT
JWT_ACCESS_LIFETIME_MIN=60
JWT_REFRESH_LIFETIME_DAYS=7

# Redis/Celery
REDIS_URL=redis://localhost:6379/0

# Email (opcional)
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password
DEFAULT_FROM_EMAIL=Sócrates <noreply@yourcompany.com>
```

### Herramientas Externas Requeridas

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install nmap openssl

# CentOS/RHEL
sudo yum install nmap openssl

# macOS
brew install nmap openssl
```

## 📊 Uso del Sistema

### 1. Primer Acceso
1. Acceder a http://localhost:3000
2. Iniciar sesión con el superusuario creado
3. Configurar MFA desde el perfil de usuario
4. Crear clientes y asignar permisos

### 2. Registrar Certificados
1. Ir a **Certificados** → **Nuevo Certificado**
2. Completar: IP/URL, puerto, protocolo, cliente
3. El sistema validará unicidad y ejecutará análisis inicial

### 3. Análisis Automáticos
- **Vitalidad**: Se verifica cada 5 minutos
- **Análisis SSL**: Cada hora según frecuencia configurada
- **Alertas**: Diario para certificados próximos a expirar

### 4. Generar Reportes
1. Ir a **Reportes** → **Generar Reporte**
2. Seleccionar cliente, tipo y formato
3. El reporte se procesará en segundo plano
4. Descargar cuando esté completado

## 🛠️ API Endpoints

### Autenticación
- `POST /api/v1/auth/login/` - Login inicial
- `POST /api/v1/auth/mfa/verify/` - Verificar código MFA
- `POST /api/v1/auth/mfa/setup/` - Configurar MFA
- `GET /api/v1/auth/profile/` - Obtener perfil

### Certificados
- `GET /api/v1/certificates/` - Listar certificados
- `POST /api/v1/certificates/` - Crear certificado
- `POST /api/v1/certificates/{id}/check_vitality/` - Verificar vitalidad

### Análisis
- `GET /api/v1/analysis/` - Historial de análisis
- `POST /api/v1/analysis/run_analysis/` - Ejecutar análisis manual
- `GET /api/v1/analysis/dashboard_stats/` - Estadísticas

### Reportes
- `POST /api/v1/reports/certificates/` - Generar reporte
- `GET /api/v1/reports/{job_id}/` - Estado del reporte
- `GET /api/v1/reports/history/` - Historial

## 🔒 Parámetros Monitoreados

### Certificado SSL/TLS
- Common Name, SANs, Issuer, Subject
- Fechas de validez y días restantes
- Algoritmo de firma y tamaño de clave
- Estado de revocación (CRL/OCSP)

### Protocolos y Cifrados
- Versiones TLS soportadas (1.0-1.3)
- Cifrados disponibles y débiles
- Perfect Forward Secrecy (PFS)
- Detección SSLv2/SSLv3 vulnerables

### Vulnerabilidades
- Heartbleed (CVE-2014-0160)
- POODLE (CVE-2014-3566) 
- DROWN (CVE-2016-0800)
- BEAST, CRIME, BREACH
- Logjam, FREAK

### Seguridad Web
- HSTS, Expect-CT, HPKP headers
- Certificate Transparency
- OCSP Stapling
- SNI support

## 🔧 Tareas de Mantenimiento

### Limpieza de Datos
```bash
# Eliminar análisis antiguos (> 30 días)
python manage.py shell -c "
from analysis.tasks import cleanup_old_analysis
cleanup_old_analysis.apply()
"
```

### Verificación Manual
```bash
# Verificar vitalidad de todos los certificados
python manage.py shell -c "
from analysis.tasks import check_certificate_vitality
check_certificate_vitality.apply()
"
```

### Backup de Base de Datos
```bash
# MySQL dump
mysqldump -u socrates -p socrates > backup_$(date +%Y%m%d).sql

# Restaurar
mysql -u socrates -p socrates < backup_20240101.sql
```

## 📈 Monitoreo y Logs

### Logs del Sistema
- **Django**: `logs/django.log`
- **Celery**: `logs/celery.log`
- **Análisis**: Almacenados en BD con timestamps

### Métricas Clave
- Certificados monitoreados
- Análisis exitosos/fallidos
- Vulnerabilidades críticas detectadas
- Tiempo de respuesta promedio

## 🤝 Contribución

1. Fork del proyecto
2. Crear rama feature (`git checkout -b feature/nueva-funcionalidad`)
3. Commit de cambios (`git commit -am 'Agregar nueva funcionalidad'`)
4. Push a la rama (`git push origin feature/nueva-funcionalidad`)
5. Crear Pull Request

## 📄 Licencia

Este proyecto está licenciado bajo la Licencia MIT - ver archivo [LICENSE](LICENSE) para detalles.

## 🆘 Soporte

- **Documentación**: `/docs/` en el repositorio
- **Issues**: Crear issue en GitHub
- **API Docs**: http://localhost:8000/api/schema/swagger/
- **Wiki**: Consultar wiki del repositorio

---

**Desarrollado para el equipo de Hacking Ético** - Automatización de vigilancia de certificados digitales con análisis avanzado y reportería completa.