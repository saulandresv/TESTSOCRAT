Fase 0 — Fundaciones
 Infra

 infra/docker-compose.yml con mysql, redis, backend, frontend

 infra/.env (variables de DB, JWT, etc.)

 Red interna y volúmenes persistentes para MySQL

 Backend bootstrap (Django + DRF)

 Crear proyecto backend/ (Django 5, DRF, CORS)

 Configurar MySQL en settings.py (charset utf8mb4)

 DRF Spectacular (OpenAPI), CORS, Logging básico

 JWT (djangorestframework-simplejwt) con rotación de refresh

 Celery + Celery Beat + Redis (broker/result backend)

 pre-commit (black, isort, flake8)

 GitHub Actions / CI básico (lint + tests)

 Frontend bootstrap (React)

 Crear proyecto frontend/ (Vite o Next)

 Axios o RTK Query, React Router

 Tema base y layout (header, sidebar)

DoD Fase 0

 docker-compose up levanta MySQL, Redis y ambos servicios

 GET /api/schema/ sirve OpenAPI

Fase 1 — Seguridad y entidades base
Backend
 App accounts

 User model (email como username, name, role={ADMIN,ANALISTA,CLIENTE}, status, last_login)

 MFA TOTP: mfa_secret, mfa_enabled

 Endpoints:

 POST /api/v1/auth/login (retorna mfa_required o JWT)

 POST /api/v1/auth/mfa/verify

 POST /api/v1/auth/refresh

 POST /api/v1/auth/mfa/setup (QR/base32)

 Permisos DRF por rol

 App clients

 Modelo Client(id, name, created_at, status)

 CRUD:

 GET/POST /clients

 GET/PUT /clients/{id}

 POST /clients/{id}/disable (validaciones)

 App access

 Modelo UserClientAccess(user, client, level={lectura,escritura}) (unique)

 Endpoints:

 GET/POST /access

 PUT/DELETE /access/{id}

 Atajo: GET /users/{email}/access, POST /users/{email}/clients

 Usuarios (ADMIN)

 GET/POST /users

 GET/PUT/DELETE /users/{email}

Frontend
 Pantallas: Login → MFA → Dashboard

 Admin: Usuarios (lista/crear/editar), Clientes (lista/CRUD), Accesos (asignar)

 Guardas por rol y nivel

DoD Fase 1

 Flujos de login y MFA operativos

 Admin crea cliente y asigna accesos a usuarios

Fase 2 — Certificados y vitalidad
Backend
 App certs

 Modelo Certificate(client, name?, url?, ip?, port, protocol, freq_days, next_review_at, last_review_at, expiration_date, active)

 Regla de unicidad: (url OR ip) + port único entre todos los clientes

 Modelo VitalityStatus(certificate, checked_at, status={up,down})

 Endpoints:

 GET /certificates?client=&q=&protocol=&expires_before=&vitality=

 POST /certificates

 GET/PUT/DELETE /certificates/{id}

 POST /certificates/{id}/check_vitality

 GET /certificates/{id}/vitality/latest

 GET /certificates/{id}/vitality?from=&to=

Frontend
 Vista de certificados con filtros/orden (cliente, expiración, vitalidad, puerto/protocolo)

 Detalle y edición; botón “Verificar vitalidad”

DoD Fase 2

 Se puede registrar/editar/borrar certificados respetando duplicidad

 Listado con filtros y vitalidad visible

Fase 3 — Análisis automáticos y manuales
Backend
 App analysis

 Modelo Analysis(certificate, kind, success, started_at, finished_at, notes)

 Subtablas: TLSParams, SSHParams, WebParams, Vuln, CertChain, OtherParams

 Tarea periódica Celery Beat:

 Selecciona certificados con next_review_at <= now()

 Encola run_certificate_analysis(certificate_id)

 Actualiza last_review_at y next_review_at

 Integración con herramientas (sslyze, nmap, etc.) vía adaptador

 Endpoints:

 GET /analysis?client=&certificate=&success=&from=&to=

 GET /analysis/{id}

 POST /analysis/run { certificate_ids: [...] } (manual)

Frontend
 Vista de historial de análisis y detalle de resultados

 Botón “Ejecutar análisis ahora” (por certificado o lote)

DoD Fase 3

 Scheduler ejecuta análisis y persiste parámetros

 Ejecución manual disponible

Fase 4 — Reportes y auditoría
Backend
 App reports

 Generación de resumen y detallado (PDF/XLSX/JSON)

 Job asíncrono y almacenamiento en /media/reports/

 Endpoints:

 POST /reports/certificates { client_id, type, format } → 202 (job_id)

 GET /reports/{job_id} (estado y URL)

 GET /reports/history?client=

 Auditoría

 AuditLog(user, action, entity, entity_id, meta, created_at)

 GET /audit?user=&action=&entity=&from=&to=

Frontend
 Pantalla para solicitar/descargar reportes

 Historial y estados de jobs

DoD Fase 4

 Reporte PDF/Excel descargable y trazabilidad en auditoría

Fase 5 — Calidad y endurecimiento
 Tests (unitarios y de API) > 80% líneas en apps críticas

 Seeds/fixtures (usuario admin, cliente demo)

 Rate limiting, CORS estricto, headers de seguridad

 Backups de MySQL y rotación de logs

 Documentación: docs/DECISION-RECORDS.md, docs/ERD.md, docs/SECURITY.md

Endpoints (resumen “cheat sheet”)
Auth: POST /auth/login, POST /auth/mfa/verify, POST /auth/refresh, POST /auth/mfa/setup

Users (ADMIN): GET/POST /users, GET/PUT/DELETE /users/{email}, GET /users/{email}/access

Access (ADMIN): GET/POST /access, PUT/DELETE /access/{id}

Clients: GET/POST /clients, GET/PUT /clients/{id}, POST /clients/{id}/disable

Certificates: GET/POST /certificates, GET/PUT/DELETE /certificates/{id}, POST /certificates/{id}/check_vitality, GET /certificates/{id}/vitality*

Analysis: GET /analysis, POST /analysis/run, GET /analysis/{id}

Reports: POST /reports/certificates, GET /reports/{job_id}, GET /reports/history

Audit: GET /audit

Variables de entorno sugeridas
ini
Copiar
Editar
MYSQL_HOST=mysql
MYSQL_DB=socrates
MYSQL_USER=socrates
MYSQL_PASSWORD=********

DJANGO_SECRET_KEY=...
DJANGO_DEBUG=false
ALLOWED_HOSTS=*
CORS_ALLOWED_ORIGINS=http://localhost:5173

JWT_SIGNING_KEY=...
JWT_ACCESS_LIFETIME_MIN=60
JWT_REFRESH_LIFETIME_DAYS=7

REDIS_URL=redis://redis:6379/0
Primeros comandos (guía rápida)
bash
Copiar
Editar
# Infra
docker compose -f infra/docker-compose.yml up -d

# Backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install django djangorestframework djangorestframework-simplejwt drf-spectacular
pip install mysqlclient django-environ django-cors-headers celery redis
django-admin startproject config .
python manage.py startapp accounts
python manage.py startapp clients
python manage.py startapp access
python manage.py startapp certs
python manage.py startapp analysis
python manage.py startapp reports
python manage.py migrate
python manage.py createsuperuser

# Frontend (Vite)
cd ../frontend
npm create vite@latest
npm i axios @reduxjs/toolkit react-redux react-router-dom
npm run dev
