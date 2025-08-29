#!/bin/bash

# 🔒 Proyecto Sócrates - Script de Inicio Rápido
# Sistema de Monitoreo SSL/TLS

set -e

echo "🚀 Iniciando configuración del Proyecto Sócrates..."
echo "=================================================="

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Función para imprimir con colores
print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Verificar prerequisitos
check_prerequisites() {
    print_info "Verificando prerequisitos del sistema..."
    
    # Verificar Docker
    if command -v docker &> /dev/null; then
        print_status "Docker encontrado"
    else
        print_error "Docker no está instalado. Por favor instala Docker primero."
        exit 1
    fi
    
    # Verificar Docker Compose
    if command -v docker-compose &> /dev/null; then
        print_status "Docker Compose encontrado"
    else
        print_error "Docker Compose no está instalado. Por favor instala Docker Compose primero."
        exit 1
    fi
    
    # Verificar herramientas SSL
    if command -v nmap &> /dev/null; then
        print_status "nmap encontrado"
    else
        print_warning "nmap no encontrado. Se instalará en el contenedor Docker."
    fi
    
    if command -v sslscan &> /dev/null; then
        print_status "sslscan encontrado"
    else
        print_warning "sslscan no encontrado. Se instalará en el contenedor Docker."
    fi
}

# Configurar variables de entorno
setup_environment() {
    print_info "Configurando variables de entorno..."
    
    if [ ! -f backend/.env ]; then
        cat > backend/.env << EOF
# Django Configuration
DEBUG=True
SECRET_KEY=django-insecure-desarrollo-solo-para-testing-no-usar-en-produccion
ALLOWED_HOSTS=localhost,127.0.0.1,0.0.0.0

# Database Configuration
DB_ENGINE=django.db.backends.mysql
DB_NAME=socrates
DB_USER=socrates_user
DB_PASSWORD=socrates_password_123
DB_HOST=mysql
DB_PORT=3306

# Redis Configuration
REDIS_URL=redis://redis:6379/0

# SSL Analysis Configuration
SSL_ANALYSIS_TIMEOUT=30
MAX_CONCURRENT_ANALYSES=5
ANALYSIS_RETENTION_DAYS=90

# CORS Configuration
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000

# Celery Configuration
CELERY_BROKER_URL=redis://redis:6379/0
CELERY_RESULT_BACKEND=redis://redis:6379/0
EOF
        print_status "Archivo .env creado en backend/"
    else
        print_status "Archivo .env ya existe en backend/"
    fi
}

# Crear docker-compose.yml si no existe
setup_docker_compose() {
    print_info "Verificando configuración de Docker Compose..."
    
    if [ ! -f docker-compose.yml ]; then
        cat > docker-compose.yml << EOF
version: '3.8'

services:
  mysql:
    image: mysql:8.0
    container_name: socrates_mysql
    environment:
      MYSQL_DATABASE: socrates
      MYSQL_USER: socrates_user
      MYSQL_PASSWORD: socrates_password_123
      MYSQL_ROOT_PASSWORD: root_password_123
    ports:
      - "3306:3306"
    volumes:
      - mysql_data:/var/lib/mysql
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost"]
      timeout: 20s
      retries: 10

  redis:
    image: redis:7-alpine
    container_name: socrates_redis
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile.dev
    container_name: socrates_backend
    ports:
      - "8000:8000"
    volumes:
      - ./backend:/app
    environment:
      - DEBUG=True
    depends_on:
      mysql:
        condition: service_healthy
      redis:
        condition: service_started
    command: >
      sh -c "python manage.py migrate &&
             python manage.py collectstatic --noinput &&
             python manage.py runserver 0.0.0.0:8000"

  celery_worker:
    build:
      context: ./backend
      dockerfile: Dockerfile.dev
    container_name: socrates_celery_worker
    volumes:
      - ./backend:/app
    depends_on:
      - mysql
      - redis
      - backend
    command: celery -A config worker -l info

  celery_beat:
    build:
      context: ./backend
      dockerfile: Dockerfile.dev
    container_name: socrates_celery_beat
    volumes:
      - ./backend:/app
    depends_on:
      - mysql
      - redis
      - backend
    command: celery -A config beat -l info

  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    container_name: socrates_frontend
    ports:
      - "3000:3000"
    volumes:
      - ./frontend:/app
      - /app/node_modules
    environment:
      - REACT_APP_API_URL=http://localhost:8000
    depends_on:
      - backend

volumes:
  mysql_data:
  redis_data:
EOF
        print_status "Docker Compose configurado"
    else
        print_status "docker-compose.yml ya existe"
    fi
}

# Crear Dockerfile para frontend si no existe
setup_frontend_dockerfile() {
    if [ ! -f frontend/Dockerfile ]; then
        cat > frontend/Dockerfile << EOF
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

EXPOSE 3000

CMD ["npm", "start"]
EOF
        print_status "Dockerfile creado para frontend"
    fi
}

# Levantar servicios con Docker
start_services() {
    print_info "Levantando servicios con Docker..."
    
    # Construir y levantar servicios
    docker-compose up --build -d mysql redis
    
    print_info "Esperando que MySQL esté listo..."
    sleep 20
    
    # Levantar backend
    docker-compose up --build -d backend
    
    print_info "Esperando que el backend esté listo..."
    sleep 15
    
    # Levantar workers de Celery
    docker-compose up -d celery_worker celery_beat
    
    # Levantar frontend
    docker-compose up --build -d frontend
    
    print_status "Todos los servicios están corriendo"
}

# Poblar base de datos con datos de ejemplo
populate_database() {
    print_info "Poblando base de datos con datos de ejemplo..."
    
    # Crear superusuario
    docker-compose exec backend python manage.py shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(email='admin@socrates.com').exists():
    User.objects.create_superuser('admin@socrates.com', 'admin123')
    print('Superusuario creado: admin@socrates.com / admin123')
else:
    print('Superusuario ya existe')
"
    
    # Ejecutar seeder
    docker-compose exec backend python manage.py seed_certificates --count 15
    
    print_status "Base de datos poblada con datos de ejemplo"
}

# Mostrar información final
show_final_info() {
    echo ""
    echo "🎉 ¡Proyecto Sócrates configurado exitosamente!"
    echo "============================================="
    echo ""
    print_info "URLs del sistema:"
    echo "  🌐 Frontend:     http://localhost:3000"
    echo "  🔧 Backend API:  http://localhost:8000"
    echo "  🔧 Admin Panel:  http://localhost:8000/admin"
    echo ""
    print_info "Credenciales de administrador:"
    echo "  📧 Email:    admin@socrates.com"
    echo "  🔑 Password: admin123"
    echo ""
    print_info "Servicios disponibles:"
    echo "  🗄️  MySQL:   localhost:3306"
    echo "  🔴 Redis:    localhost:6379"
    echo ""
    print_info "Comandos útiles:"
    echo "  🔍 Ver logs:           docker-compose logs -f"
    echo "  🛑 Parar servicios:    docker-compose down"
    echo "  🔄 Reiniciar:          docker-compose restart"
    echo "  🧹 Limpiar todo:       docker-compose down -v"
    echo ""
    print_warning "Nota: Este es un entorno de desarrollo. No usar en producción."
    echo ""
    print_status "¡El sistema está listo para usar! 🚀"
}

# Función principal
main() {
    echo "🔒 Configurando Proyecto Sócrates - Sistema de Monitoreo SSL/TLS"
    echo "================================================================="
    echo ""
    
    check_prerequisites
    echo ""
    
    setup_environment
    echo ""
    
    setup_docker_compose
    setup_frontend_dockerfile
    echo ""
    
    start_services
    echo ""
    
    print_info "Esperando que todos los servicios se estabilicen..."
    sleep 30
    
    populate_database
    echo ""
    
    show_final_info
}

# Verificar si se está ejecutando desde el directorio correcto
if [ ! -f "backend/manage.py" ] || [ ! -f "frontend/package.json" ]; then
    print_error "Este script debe ejecutarse desde el directorio raíz del proyecto"
    print_error "Asegúrate de estar en el directorio que contiene las carpetas 'backend' y 'frontend'"
    exit 1
fi

# Ejecutar función principal
main

# Mantener los logs visibles
print_info "Mostrando logs del sistema (Ctrl+C para salir)..."
docker-compose logs -f