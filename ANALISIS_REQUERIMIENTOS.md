# Análisis de Requerimientos - Proyecto Sócrates

## Estado Actual vs. Requerimientos Oficiales

### ❌ **Estado Actual - Muy Limitado:**
- Solo app `clients` con modelo básico (sin migraciones aplicadas)
- Sin autenticación implementada
- Sin apps principales: `accounts`, `access`, `certs`, `analysis`
- BD sin crear - el modelo actual no refleja los requerimientos
- La app `clients` NO está registrada en `INSTALLED_APPS`

### ✅ **Lo que SE NECESITA según documentos:**

#### **1. Base de Datos Completa (11 tablas):**
```sql
usuarios                    # con MFA, roles: ADMIN/CLIENTE/ANALISTA
clientes                   # información básica de clientes
usuario_cliente_acceso     # control de permisos por cliente
certificados              # IP/URL, puerto, protocolo, frecuencias
estado_vitalidad          # monitoreo up/down con timestamps
analisis                  # jobs de análisis con Celery
parametros_generales      # CN, SAN, issuer, validez, expiración
parametros_tls           # protocolos, cifrados, vulnerabilidades
vulnerabilidades         # Heartbleed, POODLE, DROWN, etc.
cadena_certificacion     # validación de chain SSL
parametros_ssh/web/otros # específicos por protocolo
```

#### **2. Funcionalidades Críticas Faltantes:**
- **Autenticación MFA** (TOTP con QR codes)
- **Sistema de roles** y control de acceso por cliente
- **Gestión de certificados** (registrar, validar unicidad IP+puerto)
- **Análisis automáticos** con Celery Beat (nmap, sslyze, sslscan)
- **Monitoreo de vitalidad** (indicadores verde/rojo con timestamps)
- **Generación de reportes** (PDF/Excel por cliente)
- **Scheduler para análisis** recurrentes (semanal/quincenal/mensual)
- **Frontend React** (completamente ausente)

#### **3. Apps Django Requeridas:**
```bash
accounts/     # Usuarios, MFA, autenticación, roles
access/       # Control acceso usuario-cliente  
certs/        # Certificados, vitalidad, gestión
analysis/     # Análisis automáticos, parámetros SSL/TLS
reports/      # Generación reportes PDF/Excel
audit/        # Logs de auditoría (opcional pero recomendado)
```

#### **4. Parámetros de Certificados a Monitorear:**

**A) Generales del Certificado:**
- Common Name (CN), Alternative Names (SAN)
- Issuer, Subject, Serial Number, Versión
- Algoritmo de Firma, Public Key (tipo, tamaño)
- Fechas de validez y expiración
- Estado de revocación (CRL/OCSP)

**B) Protocolos y Cifradores SSL/TLS:**
- Protocolos soportados (TLS 1.0-1.3, SSLv2/v3)
- Cifrados disponibles y débiles
- Perfect Forward Secrecy (PFS)

**C) Vulnerabilidades Conocidas:**
- Heartbleed, POODLE, DROWN
- BEAST, CRIME, BREACH
- Logjam, FREAK

**D) Cadena de Certificación:**
- Validación completa hasta raíz
- Certificados intermedios faltantes
- Auto-firmados

**E) SSH (cuando aplique):**
- Versión, algoritmos, fingerprint
- Tipo y longitud de clave

**F) Web/APIs:**
- Headers HTTP (HSTS, Expect-CT, HPKP)
- SNI, OCSP Stapling
- Tiempo de respuesta SSL

#### **5. Tecnologías Faltantes:**
- **Celery + Redis** para análisis asíncronos
- **Herramientas externas** (nmap, sslyze, sslscan)
- **Generación PDF/Excel** (reportlab, openpyxl)
- **TOTP para MFA** (pyotp)
- **Frontend React** con Vite
- **Integración con herramientas de análisis SSL**

#### **6. Casos de Uso Principales:**

**Autenticación:**
- Login con email/contraseña
- Validación MFA con código TOTP
- Gestión de tokens JWT

**Gestión de Certificados:**
- Registrar certificado (IP/URL + puerto + cliente)
- Validar unicidad (no duplicados entre clientes)
- Análisis inicial automático al registrar

**Monitoreo y Análisis:**
- Análisis automáticos programados (Celery Beat)
- Verificación de vitalidad (up/down) varias veces al día
- Integración con nmap, sslyze para obtener parámetros

**Reportes:**
- Generación PDF/Excel por cliente
- Reportes resumidos y detallados
- Descarga de informes para entrega al cliente

**Control de Acceso:**
- Usuarios con roles (ADMIN/ANALISTA/CLIENTE)
- Asignación de acceso por cliente (lectura/escritura)
- Separación de datos por cliente

## **Próximos Pasos Prioritarios:**

### **Paso 1 - Configuración Base:**
```bash
# 1. Registrar app clients en settings.py
# 2. Crear y aplicar migraciones
python manage.py makemigrations clients
python manage.py migrate

# 3. Crear apps faltantes
python manage.py startapp accounts
python manage.py startapp access  
python manage.py startapp certs
python manage.py startapp analysis
python manage.py startapp reports
```

### **Paso 2 - Modelos Críticos:**
1. **accounts/models.py** - Usuario con MFA y roles
2. **access/models.py** - UserClientAccess para permisos
3. **certs/models.py** - Certificate y VitalityStatus
4. **analysis/models.py** - Analysis y todas las tablas de parámetros

### **Paso 3 - Autenticación y Permisos:**
1. Sistema JWT con MFA
2. Middleware de permisos por cliente
3. API endpoints de autenticación

### **Paso 4 - Motor de Análisis:**
1. Configurar Celery + Redis
2. Tareas para análisis con herramientas externas
3. Scheduler para análisis recurrentes

### **Paso 5 - Frontend:**
1. Setup React con Vite
2. Autenticación y routing
3. Interfaces para gestión de certificados

## **Conclusión:**
El proyecto está en estado **inicial (5% completado)**. Se requiere desarrollo completo de:
- 11 tablas de base de datos
- 5+ apps Django con sus modelos y APIs
- Sistema completo de autenticación MFA
- Motor de análisis con herramientas externas  
- Frontend React desde cero
- Configuración Celery/Redis para tareas asíncronas

**Es básicamente un desarrollo completo** partiendo de la infraestructura Docker existente.