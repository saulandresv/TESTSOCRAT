# Inventario Completo de Archivos del Proyecto Sócrates

Este documento contiene la lista completa de todos los archivos del proyecto organizados por categorías y directorios, con checkboxes para realizar seguimiento de la revisión de cada archivo.

## 📋 Resumen General
- **Total de archivos identificados**: 393 archivos
- **Directorios principales**: backend, frontend, infra, nginx, scripts
- **Tipos de archivos**: Python, JavaScript, HTML, CSS, Docker, Config, Docs

---

## 🔧 Archivos de Configuración Principal

### Configuración del Proyecto
- [ ] `./.claude/settings.local.json` - Configuración local de Claude
- [ ] `./.gitignore` - Archivos ignorados por Git
- [ ] `./docker-compose.yml` - Configuración Docker Compose desarrollo
- [ ] `./docker-compose.prod.yml` - Configuración Docker Compose producción
- [ ] `./inicio_rapido.sh` - Script de inicio rápido
- [ ] `./socrates_dump.sql` - Dump de base de datos

### Archivos Temporales y Test
- [ ] `./qr_response.json` - Respuesta QR temporal
- [ ] `./temp_response.json` - Respuesta temporal
- [ ] `./test-mfa.html` - Test de autenticación MFA

---

## 📚 Documentación

### Documentos Principales
- [ ] `./README.md` - Documentación principal del proyecto
- [ ] `./ANALISIS_REQUERIMIENTOS.md` - Análisis de requerimientos
- [ ] `./COMANDOS_RAPIDOS.md` - Comandos rápidos de uso
- [ ] `./DEPLOYMENT.md` - Guía de despliegue
- [ ] `./DESARROLLO_FASE_1.md` - Documentación fase 1 de desarrollo
- [ ] `./GUIA_USO.md` - Guía de uso del sistema
- [ ] `./TODO.md` - Lista de tareas pendientes

---

## 🐍 Backend (Django)

### Configuración Base del Backend
- [ ] `./backend/.env` - Variables de entorno
- [ ] `./backend/Dockerfile.dev` - Dockerfile para desarrollo
- [ ] `./backend/Dockerfile.prod` - Dockerfile para producción
- [ ] `./backend/docker-entrypoint.prod.sh` - Script de entrada para producción
- [ ] `./backend/get-pip.py` - Instalador de pip
- [ ] `./backend/manage.py` - Comando principal de Django
- [ ] `./backend/requirements.txt` - Dependencias de desarrollo
- [ ] `./backend/requirements.prod.txt` - Dependencias de producción
- [ ] `./backend/settings_dev.py` - Configuración de desarrollo
- [ ] `./backend/settings_temp.py` - Configuración temporal
- [ ] `./backend/production.env.example` - Ejemplo de variables de producción
- [ ] `./backend/temp_apps.py` - Aplicaciones temporales
- [ ] `./backend/celerybeat-schedule` - Programación de Celery
- [ ] `./backend/venv/pyvenv.cfg` - Configuración de entorno virtual

### Configuración Principal (config/)
- [ ] `./backend/config/__init__.py` - Inicialización del paquete
- [ ] `./backend/config/asgi.py` - Configuración ASGI
- [ ] `./backend/config/celery.py` - Configuración de Celery
- [ ] `./backend/config/settings.py` - Configuración principal de Django
- [ ] `./backend/config/urls.py` - URLs principales
- [ ] `./backend/config/wsgi.py` - Configuración WSGI

### Módulo de Cuentas (accounts/)
- [ ] `./backend/accounts/__init__.py` - Inicialización del módulo
- [ ] `./backend/accounts/admin.py` - Configuración del admin
- [ ] `./backend/accounts/apps.py` - Configuración de la aplicación
- [ ] `./backend/accounts/models.py` - Modelos de usuarios y cuentas
- [ ] `./backend/accounts/serializers.py` - Serializadores de la API
- [ ] `./backend/accounts/tests.py` - Tests del módulo
- [ ] `./backend/accounts/urls.py` - URLs del módulo
- [ ] `./backend/accounts/views.py` - Vistas del módulo
- [ ] `./backend/accounts/viewsets.py` - ViewSets de la API

#### Migraciones de Accounts
- [ ] `./backend/accounts/migrations/__init__.py` - Inicialización de migraciones
- [ ] `./backend/accounts/migrations/0001_initial.py` - Migración inicial
- [ ] `./backend/accounts/migrations/0002_user_ultimo_login_alter_user_table.py` - Migración último login
- [ ] `./backend/accounts/migrations/0003_user_mfa_enabled.py` - Migración MFA
- [ ] `./backend/accounts/migrations/0004_alter_user_rol_userclientaccess.py` - Migración roles y acceso

### Módulo de Acceso (access/)
- [ ] `./backend/access/__init__.py` - Inicialización del módulo
- [ ] `./backend/access/admin.py` - Configuración del admin
- [ ] `./backend/access/apps.py` - Configuración de la aplicación
- [ ] `./backend/access/models.py` - Modelos de control de acceso
- [ ] `./backend/access/tests.py` - Tests del módulo
- [ ] `./backend/access/views.py` - Vistas del módulo

#### Migraciones de Access
- [ ] `./backend/access/migrations/__init__.py` - Inicialización de migraciones
- [ ] `./backend/access/migrations/0001_initial.py` - Migración inicial
- [ ] `./backend/access/migrations/0002_initial.py` - Segunda migración inicial

### Módulo de Análisis (analysis/)
- [ ] `./backend/analysis/__init__.py` - Inicialización del módulo
- [ ] `./backend/analysis/admin.py` - Configuración del admin
- [ ] `./backend/analysis/analysis_engine.py` - Motor de análisis principal
- [ ] `./backend/analysis/apps.py` - Configuración de la aplicación
- [ ] `./backend/analysis/external_tools.py` - Herramientas externas
- [ ] `./backend/analysis/middleware.py` - Middleware del módulo
- [ ] `./backend/analysis/models.py` - Modelos de análisis
- [ ] `./backend/analysis/serializers.py` - Serializadores de la API
- [ ] `./backend/analysis/ssh_analyzer.py` - Analizador SSH
- [ ] `./backend/analysis/tasks.py` - Tareas de Celery
- [ ] `./backend/analysis/tests.py` - Tests del módulo
- [ ] `./backend/analysis/tests_rate_limiting.py` - Tests de rate limiting
- [ ] `./backend/analysis/urls.py` - URLs del módulo
- [ ] `./backend/analysis/views.py` - Vistas del módulo
- [ ] `./backend/analysis/vulnerability_scanner.py` - Escáner de vulnerabilidades

#### Migraciones de Analysis
- [ ] `./backend/analysis/migrations/__init__.py` - Inicialización de migraciones
- [ ] `./backend/analysis/migrations/0001_initial.py` - Migración inicial

### Módulo de Certificados (certs/)
- [ ] `./backend/certs/__init__.py` - Inicialización del módulo
- [ ] `./backend/certs/admin.py` - Configuración del admin
- [ ] `./backend/certs/apps.py` - Configuración de la aplicación
- [ ] `./backend/certs/models.py` - Modelos de certificados
- [ ] `./backend/certs/serializers.py` - Serializadores de la API
- [ ] `./backend/certs/tests.py` - Tests del módulo
- [ ] `./backend/certs/urls.py` - URLs del módulo
- [ ] `./backend/certs/views.py` - Vistas del módulo

#### Comandos de Gestión de Certificados
- [ ] `./backend/certs/management/__init__.py` - Inicialización de comandos
- [ ] `./backend/certs/management/commands/__init__.py` - Inicialización de comandos
- [ ] `./backend/certs/management/commands/seed_certificates.py` - Comando para poblar certificados

#### Migraciones de Certificados
- [ ] `./backend/certs/migrations/__init__.py` - Inicialización de migraciones
- [ ] `./backend/certs/migrations/0001_initial.py` - Migración inicial
- [ ] `./backend/certs/migrations/0002_remove_certificate_unique_ip_puerto_and_more.py` - Migración restricciones IP/Puerto
- [ ] `./backend/certs/migrations/0003_remove_certificate_unique_cliente_ip_puerto_and_more.py` - Migración restricciones cliente

### Módulo de Clientes (clients/)
- [ ] `./backend/clients/__init__.py` - Inicialización del módulo
- [ ] `./backend/clients/admin.py` - Configuración del admin
- [ ] `./backend/clients/apps.py` - Configuración de la aplicación
- [ ] `./backend/clients/models.py` - Modelos de clientes
- [ ] `./backend/clients/serializers.py` - Serializadores de la API
- [ ] `./backend/clients/tests.py` - Tests del módulo
- [ ] `./backend/clients/url.py` - URLs del módulo
- [ ] `./backend/clients/views.py` - Vistas del módulo

#### Migraciones de Clientes
- [ ] `./backend/clients/migrations/__init__.py` - Inicialización de migraciones
- [ ] `./backend/clients/migrations/0001_initial.py` - Migración inicial

### Módulo de Notificaciones (notifications/)
- [ ] `./backend/notifications/__init__.py` - Inicialización del módulo
- [ ] `./backend/notifications/email_service.py` - Servicio de email
- [ ] `./backend/notifications/tasks.py` - Tareas de notificaciones

### Módulo de Reportes (reports/)
- [ ] `./backend/reports/__init__.py` - Inicialización del módulo
- [ ] `./backend/reports/admin.py` - Configuración del admin
- [ ] `./backend/reports/apps.py` - Configuración de la aplicación
- [ ] `./backend/reports/generators.py` - Generadores de reportes
- [ ] `./backend/reports/models.py` - Modelos de reportes
- [ ] `./backend/reports/serializers.py` - Serializadores de la API
- [ ] `./backend/reports/tasks.py` - Tareas de Celery para reportes
- [ ] `./backend/reports/tests.py` - Tests del módulo
- [ ] `./backend/reports/urls.py` - URLs del módulo
- [ ] `./backend/reports/views.py` - Vistas del módulo

#### Migraciones de Reportes
- [ ] `./backend/reports/migrations/__init__.py` - Inicialización de migraciones
- [ ] `./backend/reports/migrations/0001_initial.py` - Migración inicial

### Comandos de Gestión
- [ ] `./backend/management/commands/test_rate_limiting.py` - Test de rate limiting

### Templates de Email
- [ ] `./backend/templates/emails/certificate_expiry.html` - Template HTML expiración certificados
- [ ] `./backend/templates/emails/certificate_expiry.txt` - Template texto expiración certificados
- [ ] `./backend/templates/emails/vulnerability_alert.html` - Template HTML alerta vulnerabilidades
- [ ] `./backend/templates/emails/vulnerability_alert.txt` - Template texto alerta vulnerabilidades

### Logs del Sistema
- [ ] `./backend/logs/celery.log` - Logs de Celery
- [ ] `./backend/logs/django.log` - Logs de Django
- [ ] `./backend/logs/rate_limiting.log` - Logs de rate limiting

### Archivos Estáticos - Admin Django
#### CSS del Admin
- [ ] `./backend/staticfiles/admin/css/autocomplete.css` - Estilos autocompletado
- [ ] `./backend/staticfiles/admin/css/base.css` - Estilos base
- [ ] `./backend/staticfiles/admin/css/changelists.css` - Estilos listas de cambios
- [ ] `./backend/staticfiles/admin/css/dark_mode.css` - Estilos modo oscuro
- [ ] `./backend/staticfiles/admin/css/dashboard.css` - Estilos dashboard
- [ ] `./backend/staticfiles/admin/css/forms.css` - Estilos formularios
- [ ] `./backend/staticfiles/admin/css/login.css` - Estilos login
- [ ] `./backend/staticfiles/admin/css/nav_sidebar.css` - Estilos navegación
- [ ] `./backend/staticfiles/admin/css/responsive.css` - Estilos responsive
- [ ] `./backend/staticfiles/admin/css/responsive_rtl.css` - Estilos responsive RTL
- [ ] `./backend/staticfiles/admin/css/rtl.css` - Estilos RTL
- [ ] `./backend/staticfiles/admin/css/widgets.css` - Estilos widgets

#### Vendor CSS del Admin
- [ ] `./backend/staticfiles/admin/css/vendor/select2/LICENSE-SELECT2.md` - Licencia Select2
- [ ] `./backend/staticfiles/admin/css/vendor/select2/select2.css` - Estilos Select2
- [ ] `./backend/staticfiles/admin/css/vendor/select2/select2.min.css` - Estilos Select2 minificado

#### Imágenes del Admin
- [ ] `./backend/staticfiles/admin/img/LICENSE` - Licencia imágenes
- [ ] `./backend/staticfiles/admin/img/README.txt` - README imágenes
- [ ] `./backend/staticfiles/admin/img/calendar-icons.svg` - Iconos calendario
- [ ] `./backend/staticfiles/admin/img/gis/move_vertex_off.svg` - Icono GIS vértice off
- [ ] `./backend/staticfiles/admin/img/gis/move_vertex_on.svg` - Icono GIS vértice on
- [ ] `./backend/staticfiles/admin/img/icon-addlink.svg` - Icono agregar link
- [ ] `./backend/staticfiles/admin/img/icon-alert.svg` - Icono alerta
- [ ] `./backend/staticfiles/admin/img/icon-calendar.svg` - Icono calendario
- [ ] `./backend/staticfiles/admin/img/icon-changelink.svg` - Icono cambiar link
- [ ] `./backend/staticfiles/admin/img/icon-clock.svg` - Icono reloj
- [ ] `./backend/staticfiles/admin/img/icon-deletelink.svg` - Icono eliminar link
- [ ] `./backend/staticfiles/admin/img/icon-hidelink.svg` - Icono ocultar link
- [ ] `./backend/staticfiles/admin/img/icon-no.svg` - Icono no
- [ ] `./backend/staticfiles/admin/img/icon-unknown-alt.svg` - Icono desconocido alt
- [ ] `./backend/staticfiles/admin/img/icon-unknown.svg` - Icono desconocido
- [ ] `./backend/staticfiles/admin/img/icon-viewlink.svg` - Icono ver link
- [ ] `./backend/staticfiles/admin/img/icon-yes.svg` - Icono sí
- [ ] `./backend/staticfiles/admin/img/inline-delete.svg` - Icono eliminar inline
- [ ] `./backend/staticfiles/admin/img/search.svg` - Icono búsqueda
- [ ] `./backend/staticfiles/admin/img/selector-icons.svg` - Iconos selector
- [ ] `./backend/staticfiles/admin/img/sorting-icons.svg` - Iconos ordenamiento
- [ ] `./backend/staticfiles/admin/img/tooltag-add.svg` - Icono tooltip agregar
- [ ] `./backend/staticfiles/admin/img/tooltag-arrowright.svg` - Icono tooltip flecha

#### JavaScript del Admin
- [ ] `./backend/staticfiles/admin/js/SelectBox.js` - SelectBox
- [ ] `./backend/staticfiles/admin/js/SelectFilter2.js` - SelectFilter2
- [ ] `./backend/staticfiles/admin/js/actions.js` - Acciones
- [ ] `./backend/staticfiles/admin/js/admin/DateTimeShortcuts.js` - Atajos DateTime
- [ ] `./backend/staticfiles/admin/js/admin/RelatedObjectLookups.js` - Búsquedas objetos relacionados
- [ ] `./backend/staticfiles/admin/js/autocomplete.js` - Autocompletado
- [ ] `./backend/staticfiles/admin/js/calendar.js` - Calendario
- [ ] `./backend/staticfiles/admin/js/cancel.js` - Cancelar
- [ ] `./backend/staticfiles/admin/js/change_form.js` - Formulario cambio
- [ ] `./backend/staticfiles/admin/js/collapse.js` - Colapsar
- [ ] `./backend/staticfiles/admin/js/core.js` - Core
- [ ] `./backend/staticfiles/admin/js/filters.js` - Filtros
- [ ] `./backend/staticfiles/admin/js/inlines.js` - Inlines
- [ ] `./backend/staticfiles/admin/js/jquery.init.js` - Inicialización jQuery
- [ ] `./backend/staticfiles/admin/js/nav_sidebar.js` - Navegación sidebar
- [ ] `./backend/staticfiles/admin/js/popup_response.js` - Respuesta popup
- [ ] `./backend/staticfiles/admin/js/prepopulate.js` - Prepoblar
- [ ] `./backend/staticfiles/admin/js/prepopulate_init.js` - Inicialización prepoblar
- [ ] `./backend/staticfiles/admin/js/theme.js` - Tema
- [ ] `./backend/staticfiles/admin/js/urlify.js` - URLify

#### Vendor JavaScript del Admin
##### jQuery
- [ ] `./backend/staticfiles/admin/js/vendor/jquery/LICENSE.txt` - Licencia jQuery
- [ ] `./backend/staticfiles/admin/js/vendor/jquery/jquery.js` - jQuery
- [ ] `./backend/staticfiles/admin/js/vendor/jquery/jquery.min.js` - jQuery minificado

##### Select2
- [ ] `./backend/staticfiles/admin/js/vendor/select2/LICENSE.md` - Licencia Select2
- [ ] `./backend/staticfiles/admin/js/vendor/select2/select2.full.js` - Select2 completo
- [ ] `./backend/staticfiles/admin/js/vendor/select2/select2.full.min.js` - Select2 completo minificado

###### Internacionalización Select2
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/af.js` - Afrikaans
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/ar.js` - Árabe
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/az.js` - Azerbaiyano
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/bg.js` - Búlgaro
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/bn.js` - Bengalí
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/bs.js` - Bosnio
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/ca.js` - Catalán
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/cs.js` - Checo
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/da.js` - Danés
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/de.js` - Alemán
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/dsb.js` - Bajo Sorabo
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/el.js` - Griego
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/en.js` - Inglés
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/es.js` - Español
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/et.js` - Estonio
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/eu.js` - Euskera
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/fa.js` - Persa
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/fi.js` - Finés
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/fr.js` - Francés
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/gl.js` - Gallego
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/he.js` - Hebreo
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/hi.js` - Hindi
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/hr.js` - Croata
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/hsb.js` - Alto Sorabo
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/hu.js` - Húngaro
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/hy.js` - Armenio
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/id.js` - Indonesio
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/is.js` - Islandés
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/it.js` - Italiano
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/ja.js` - Japonés
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/ka.js` - Georgiano
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/km.js` - Khmer
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/ko.js` - Coreano
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/lt.js` - Lituano
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/lv.js` - Letón
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/mk.js` - Macedonio
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/ms.js` - Malayo
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/nb.js` - Noruego Bokmål
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/ne.js` - Nepalí
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/nl.js` - Holandés
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/pl.js` - Polaco
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/ps.js` - Pashto
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/pt-BR.js` - Portugués Brasil
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/pt.js` - Portugués
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/ro.js` - Rumano
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/ru.js` - Ruso
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/sk.js` - Eslovaco
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/sl.js` - Esloveno
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/sq.js` - Albanés
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/sr-Cyrl.js` - Serbio Cirílico
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/sr.js` - Serbio
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/sv.js` - Sueco
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/th.js` - Tailandés
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/tk.js` - Turcomano
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/tr.js` - Turco
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/uk.js` - Ucraniano
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/vi.js` - Vietnamita
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/zh-CN.js` - Chino Simplificado
- [ ] `./backend/staticfiles/admin/js/vendor/select2/i18n/zh-TW.js` - Chino Tradicional

##### XRegExp
- [ ] `./backend/staticfiles/admin/js/vendor/xregexp/LICENSE.txt` - Licencia XRegExp
- [ ] `./backend/staticfiles/admin/js/vendor/xregexp/xregexp.js` - XRegExp
- [ ] `./backend/staticfiles/admin/js/vendor/xregexp/xregexp.min.js` - XRegExp minificado

### Archivos Estáticos - Django REST Framework
#### CSS de REST Framework
- [ ] `./backend/staticfiles/rest_framework/css/bootstrap-theme.min.css` - Tema Bootstrap minificado
- [ ] `./backend/staticfiles/rest_framework/css/bootstrap-theme.min.css.map` - Mapa tema Bootstrap
- [ ] `./backend/staticfiles/rest_framework/css/bootstrap-tweaks.css` - Ajustes Bootstrap
- [ ] `./backend/staticfiles/rest_framework/css/bootstrap.min.css` - Bootstrap minificado
- [ ] `./backend/staticfiles/rest_framework/css/bootstrap.min.css.map` - Mapa Bootstrap
- [ ] `./backend/staticfiles/rest_framework/css/default.css` - Estilos por defecto
- [ ] `./backend/staticfiles/rest_framework/css/font-awesome-4.0.3.css` - Font Awesome
- [ ] `./backend/staticfiles/rest_framework/css/prettify.css` - Prettify

#### CSS de Documentación
- [ ] `./backend/staticfiles/rest_framework/docs/css/base.css` - Estilos base docs
- [ ] `./backend/staticfiles/rest_framework/docs/css/highlight.css` - Resaltado de sintaxis
- [ ] `./backend/staticfiles/rest_framework/docs/css/jquery.json-view.min.css` - Vista JSON jQuery

#### Imágenes de Documentación
- [ ] `./backend/staticfiles/rest_framework/docs/img/favicon.ico` - Favicon
- [ ] `./backend/staticfiles/rest_framework/docs/img/grid.png` - Grid

#### JavaScript de Documentación
- [ ] `./backend/staticfiles/rest_framework/docs/js/api.js` - API JavaScript
- [ ] `./backend/staticfiles/rest_framework/docs/js/highlight.pack.js` - Resaltado de sintaxis
- [ ] `./backend/staticfiles/rest_framework/docs/js/jquery.json-view.min.js` - Vista JSON jQuery

#### Fuentes de REST Framework
- [ ] `./backend/staticfiles/rest_framework/fonts/fontawesome-webfont.eot` - Font Awesome EOT
- [ ] `./backend/staticfiles/rest_framework/fonts/fontawesome-webfont.svg` - Font Awesome SVG
- [ ] `./backend/staticfiles/rest_framework/fonts/fontawesome-webfont.ttf` - Font Awesome TTF
- [ ] `./backend/staticfiles/rest_framework/fonts/fontawesome-webfont.woff` - Font Awesome WOFF
- [ ] `./backend/staticfiles/rest_framework/fonts/glyphicons-halflings-regular.eot` - Glyphicons EOT
- [ ] `./backend/staticfiles/rest_framework/fonts/glyphicons-halflings-regular.svg` - Glyphicons SVG
- [ ] `./backend/staticfiles/rest_framework/fonts/glyphicons-halflings-regular.ttf` - Glyphicons TTF
- [ ] `./backend/staticfiles/rest_framework/fonts/glyphicons-halflings-regular.woff` - Glyphicons WOFF
- [ ] `./backend/staticfiles/rest_framework/fonts/glyphicons-halflings-regular.woff2` - Glyphicons WOFF2

#### Imágenes de REST Framework
- [ ] `./backend/staticfiles/rest_framework/img/glyphicons-halflings-white.png` - Glyphicons blancos
- [ ] `./backend/staticfiles/rest_framework/img/glyphicons-halflings.png` - Glyphicons
- [ ] `./backend/staticfiles/rest_framework/img/grid.png` - Grid

#### JavaScript de REST Framework
- [ ] `./backend/staticfiles/rest_framework/js/ajax-form.js` - Formularios AJAX
- [ ] `./backend/staticfiles/rest_framework/js/bootstrap.min.js` - Bootstrap minificado
- [ ] `./backend/staticfiles/rest_framework/js/coreapi-0.1.1.js` - Core API
- [ ] `./backend/staticfiles/rest_framework/js/csrf.js` - CSRF
- [ ] `./backend/staticfiles/rest_framework/js/default.js` - JavaScript por defecto
- [ ] `./backend/staticfiles/rest_framework/js/jquery-3.7.1.min.js` - jQuery minificado
- [ ] `./backend/staticfiles/rest_framework/js/load-ajax-form.js` - Carga formularios AJAX
- [ ] `./backend/staticfiles/rest_framework/js/prettify-min.js` - Prettify minificado

---

## 🌐 Frontend (React + Vite)

### Configuración del Frontend
- [ ] `./frontend/.env` - Variables de entorno
- [ ] `./frontend/Dockerfile` - Dockerfile principal
- [ ] `./frontend/Dockerfile.dev` - Dockerfile para desarrollo
- [ ] `./frontend/index.html` - HTML principal
- [ ] `./frontend/package-lock.json` - Lock de dependencias
- [ ] `./frontend/package.json` - Dependencias y scripts
- [ ] `./frontend/vite.config.js` - Configuración de Vite

### Código Fuente del Frontend
- [ ] `./frontend/src/App.jsx` - Componente principal de la aplicación
- [ ] `./frontend/src/main.jsx` - Punto de entrada de la aplicación

#### Componentes
- [ ] `./frontend/src/components/Analysis.jsx` - Componente de análisis
- [ ] `./frontend/src/components/CertificateForm.jsx` - Formulario de certificados
- [ ] `./frontend/src/components/Certificates.jsx` - Lista de certificados
- [ ] `./frontend/src/components/Clients.jsx` - Gestión de clientes
- [ ] `./frontend/src/components/Dashboard.jsx` - Dashboard principal
- [ ] `./frontend/src/components/Layout.jsx` - Layout de la aplicación
- [ ] `./frontend/src/components/Login.jsx` - Componente de login
- [ ] `./frontend/src/components/Profile.jsx` - Perfil de usuario
- [ ] `./frontend/src/components/Reports.jsx` - Reportes
- [ ] `./frontend/src/components/Users.jsx` - Gestión de usuarios

#### Servicios
- [ ] `./frontend/src/services/analysis.js` - Servicio de análisis
- [ ] `./frontend/src/services/api.js` - Configuración API
- [ ] `./frontend/src/services/auth.js` - Servicio de autenticación
- [ ] `./frontend/src/services/certificates.js` - Servicio de certificados
- [ ] `./frontend/src/services/reports.js` - Servicio de reportes

### Build del Frontend
- [ ] `./frontend/dist/index.html` - HTML de producción
- [ ] `./frontend/dist/assets/index-ukp0blOq.js` - JavaScript compilado

---

## 🐳 Infraestructura y Despliegue

### Configuración de Infraestructura
- [ ] `./infra/.env` - Variables de entorno de infraestructura
- [ ] `./infra/docker-compose.yml` - Docker Compose de infraestructura
- [ ] `./infra/cookies.txt` - Cookies temporales

### Nginx
- [ ] `./nginx/nginx.prod.conf` - Configuración de Nginx para producción

### Scripts
- [ ] `./scripts/init_project.sh` - Script de inicialización del proyecto

---

## 📝 Estado de Revisión

### Leyenda
- [ ] ⚪ Sin revisar
- [x] ✅ Revisado y funcionando correctamente
- [!] ⚠️ Revisado con problemas encontrados
- [?] ❓ Requiere revisión adicional

### Resumen por Categorías
- **Documentación**: 0/7 archivos revisados
- **Backend Core**: 0/15 archivos revisados
- **Módulos Django**: 0/80+ archivos revisados
- **Frontend**: 0/25 archivos revisados
- **Infraestructura**: 0/5 archivos revisados
- **Estáticos**: 0/260+ archivos revisados

---

## 🔍 Notas de Revisión

### Archivos Críticos para Revisar Primero
1. `./backend/config/settings.py` - Configuración principal
2. `./backend/requirements.txt` - Dependencias
3. `./frontend/package.json` - Dependencias frontend
4. `./docker-compose.yml` - Configuración Docker
5. `./README.md` - Documentación principal

### Archivos con Posibles Problemas
- Archivos de migración sin aplicar
- Logs con errores
- Configuraciones temporales

---

*Documento generado automáticamente el 2025-10-02*
*Total de archivos catalogados: 393*