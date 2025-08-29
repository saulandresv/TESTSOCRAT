# 🚀 Guía de Desarrollo - Fase 1: Seguridad y Entidades Base

## 📋 Estado Actual (28 Ago 2025)

### ✅ Completado:
- Frontend React básico configurado (package.json, Dockerfile, componentes mínimos)
- Docker configurado pero requiere permisos
- Configuración SQLite alternativa creada

### ⏳ Pendiente:
- Docker containers (MySQL + Redis + Backend)
- Apps Django: accounts, access
- Autenticación JWT con MFA
- Migraciones y base de datos

---

## 🔧 Próximos Pasos (ORDEN CRÍTICO)

### **PASO 1: Arreglar Docker** 
```bash
# 1. Reiniciar terminal WSL completamente
# 2. Verificar Docker funciona:
docker --version
cd /mnt/c/Users/saulv/Desktop/i3g/proyecto-socrates/infra
docker-compose up -d mysql redis

# 3. Si funciona, continuar con backend:
docker-compose up -d backend
```

### **PASO 2: Configurar Backend en Container**
```bash
# Entrar al container backend
docker exec -it <backend-container-name> bash

# Dentro del container:
# 1. Registrar clients en INSTALLED_APPS:
# Editar config/settings.py línea 24: añadir "clients"

# 2. Crear migraciones y aplicar:
python manage.py makemigrations clients
python manage.py migrate

# 3. Crear superusuario:
python manage.py createsuperuser
```

### **PASO 3: Crear Apps Django**
```bash
# Dentro del container backend:
python manage.py startapp accounts  # Usuarios + MFA + Roles
python manage.py startapp access    # Permisos usuario-cliente

# Registrar en INSTALLED_APPS:
# "accounts",
# "access",
```

### **PASO 4: Implementar Modelos**
```python
# accounts/models.py - Usuario personalizado:
from django.contrib.auth.models import AbstractUser
class User(AbstractUser):
    email = models.EmailField(unique=True)  # Login por email
    role = models.CharField(choices=[('ADMIN','Admin'), ('CLIENTE','Cliente'), ('ANALISTA','Analista')])
    mfa_secret = models.CharField(max_length=32, blank=True)
    mfa_enabled = models.BooleanField(default=False)
    status = models.CharField(default='activo')

# access/models.py - Control de acceso:
class UserClientAccess(models.Model):
    user = models.ForeignKey('accounts.User')
    client = models.ForeignKey('clients.Client')
    level = models.CharField(choices=[('lectura','Lectura'), ('escritura','Escritura')])
```

### **PASO 5: APIs de Autenticación**
```python
# accounts/views.py - Endpoints JWT + MFA:
- POST /api/v1/auth/login      # Email/password → MFA required o JWT
- POST /api/v1/auth/mfa/verify # Código TOTP → JWT completo
- POST /api/v1/auth/refresh    # Renovar token
- POST /api/v1/auth/mfa/setup  # QR code para configurar MFA
```

### **PASO 6: APIs CRUD Básicas**
```python
# Users (solo ADMIN):
- GET/POST /api/v1/users
- GET/PUT/DELETE /api/v1/users/{email}

# Clients:
- GET/POST /api/v1/clients
- GET/PUT/DELETE /api/v1/clients/{id}
- POST /api/v1/clients/{id}/disable

# Access (ADMIN):
- GET/POST /api/v1/access
- PUT/DELETE /api/v1/access/{id}
```

---

## 🛠 Comandos de Referencia

### Docker:
```bash
# Levantar servicios
cd infra/
docker-compose up -d

# Ver logs
docker-compose logs backend
docker-compose logs mysql

# Entrar al backend
docker exec -it <backend-container> bash

# Parar servicios
docker-compose down
```

### Django (dentro del container):
```bash
# Migraciones
python manage.py makemigrations
python manage.py migrate

# Crear apps
python manage.py startapp <app_name>

# Servidor de desarrollo
python manage.py runserver 0.0.0.0:8000

# Shell interactivo
python manage.py shell
```

### Frontend:
```bash
cd frontend/
docker-compose up frontend  # O directo con npm
```

---

## 📁 Estructura de Archivos Creados

```
proyecto-socrates/
├── frontend/                    ✅ COMPLETADO
│   ├── package.json            
│   ├── Dockerfile.dev
│   ├── vite.config.js
│   ├── index.html
│   └── src/
│       ├── main.jsx
│       └── App.jsx
├── backend/
│   ├── settings_dev.py         ✅ SQLite alternativo
│   ├── config/settings.py      ❌ NECESITA: "clients" en INSTALLED_APPS
│   ├── clients/                ✅ App básica existente
│   ├── accounts/               ❌ CREAR: Usuario + MFA
│   └── access/                 ❌ CREAR: Permisos
├── infra/
│   └── docker-compose.yml      ✅ Configurado (MySQL + Redis)
└── DESARROLLO_FASE_1.md        ✅ ESTA GUÍA
```

---

## 🎯 Criterios de Éxito - Fase 1

Al completar esta fase tendrás:
- ✅ Sistema de autenticación JWT funcional
- ✅ MFA con TOTP (códigos QR)
- ✅ Roles: ADMIN, CLIENTE, ANALISTA
- ✅ Control de acceso por cliente
- ✅ APIs CRUD para usuarios y clientes
- ✅ Base de datos MySQL con migraciones
- ✅ Frontend React básico comunicándose con backend

**Tiempo estimado:** 2-3 horas

---

## 🚨 Problemas Conocidos & Soluciones

### Docker permission denied:
```bash
# Solución: Reiniciar terminal WSL después de configurar Docker Desktop
exit  # Cerrar WSL
# Abrir nueva terminal WSL
```

### Backend no encuentra Django:
```bash
# Usar el container en lugar del entorno local
docker exec -it backend_container bash
```

### Frontend no conecta con backend:
```bash
# Verificar que ambos containers están corriendo:
docker-compose ps
# Backend debe estar en puerto 8000, frontend en 5173
```

---

## 📞 Siguiente Sesión

**Para continuar en próxima sesión:**

1. **Verificar estado:** `docker-compose ps`
2. **Seguir desde PASO actual** según este documento
3. **Actualizar este archivo** cuando completes pasos

**Comando para retomar rápidamente:**
```bash
cd /mnt/c/Users/saulv/Desktop/i3g/proyecto-socrates
cat DESARROLLO_FASE_1.md  # Revisar progreso
```

---

**💡 Tip:** Guarda este archivo y úsalo como referencia. Actualízalo cuando completes cada paso.