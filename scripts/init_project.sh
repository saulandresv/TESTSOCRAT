#!/bin/bash

# 🔒 Proyecto Sócrates - Script de Inicialización
# Este script configura e inicia el proyecto completo

set -e

echo "🔒 Inicializando Proyecto Sócrates..."
echo "=================================="

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Función para mostrar mensajes
show_step() {
    echo -e "${BLUE}[PASO]${NC} $1"
}

show_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

show_warning() {
    echo -e "${YELLOW}[ADVERTENCIA]${NC} $1"
}

show_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Verificar que estamos en el directorio correcto
if [ ! -f "docker-compose.yml" ]; then
    show_error "No se encontró docker-compose.yml. Ejecute este script desde la raíz del proyecto."
    exit 1
fi

show_step "Verificando dependencias..."

# Verificar Docker
if ! command -v docker &> /dev/null; then
    show_error "Docker no está instalado. Instale Docker primero."
    exit 1
fi

# Verificar Docker Compose
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    show_error "Docker Compose no está instalado. Instale Docker Compose primero."
    exit 1
fi

show_success "Dependencias verificadas"

# Crear archivos de configuración si no existen
show_step "Configurando archivos de entorno..."

if [ ! -f "backend/.env" ]; then
    show_step "Creando backend/.env..."
    cat > backend/.env << EOF
# Base de datos
MYSQL_HOST=mysql
MYSQL_DATABASE=socrates
MYSQL_USER=socrates
MYSQL_PASSWORD=devpassword

# Seguridad
SECRET_KEY=dev-secret-key-change-in-production-$(openssl rand -hex 32)
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1,backend

# JWT
JWT_ACCESS_LIFETIME_MIN=60
JWT_REFRESH_LIFETIME_DAYS=7

# Redis/Celery
REDIS_URL=redis://redis:6379/0

# CORS
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173
EOF
    show_success "Archivo backend/.env creado"
fi

if [ ! -f "frontend/.env" ]; then
    show_step "Creando frontend/.env..."
    cat > frontend/.env << EOF
VITE_API_BASE_URL=http://localhost:8000/api/v1
EOF
    show_success "Archivo frontend/.env creado"
fi

# Construir e iniciar contenedores
show_step "Construyendo e iniciando contenedores Docker..."
docker-compose down --remove-orphans 2>/dev/null || true
docker-compose up -d --build

show_success "Contenedores iniciados"

# Esperar a que MySQL esté listo
show_step "Esperando a que MySQL esté listo..."
until docker-compose exec mysql mysqladmin ping -h"localhost" --silent; do
    sleep 2
done
show_success "MySQL está listo"

# Ejecutar migraciones
show_step "Ejecutando migraciones de base de datos..."
docker-compose exec backend python manage.py makemigrations
docker-compose exec backend python manage.py migrate
show_success "Migraciones completadas"

# Crear superusuario si no existe
show_step "Configurando usuario administrador..."
docker-compose exec backend python manage.py shell << EOF
from accounts.models import User
if not User.objects.filter(email='admin@socrates.local').exists():
    User.objects.create_superuser(
        email='admin@socrates.local',
        password='admin123',
        nombre_usuario='Administrador',
        rol='ADMIN'
    )
    print("Superusuario creado: admin@socrates.local / admin123")
else:
    print("Superusuario ya existe")
EOF
show_success "Usuario administrador configurado"

# Mostrar información del sistema
echo ""
echo "🎉 ¡Proyecto Sócrates iniciado correctamente!"
echo "==========================================="
echo ""
echo -e "${GREEN}Servicios disponibles:${NC}"
echo "• Frontend:    http://localhost:3000"
echo "• Backend:     http://localhost:8000"
echo "• API Docs:    http://localhost:8000/api/schema/swagger/"
echo "• Admin:       http://localhost:8000/admin/"
echo ""
echo -e "${YELLOW}Credenciales iniciales:${NC}"
echo "• Email:       admin@socrates.local"
echo "• Contraseña:  admin123"
echo ""
echo -e "${BLUE}Comandos útiles:${NC}"
echo "• Ver logs:           docker-compose logs -f"
echo "• Parar servicios:    docker-compose down"
echo "• Reiniciar:          docker-compose restart"
echo "• Acceder backend:    docker-compose exec backend bash"
echo ""

# Verificar que los servicios estén respondiendo
show_step "Verificando servicios..."
sleep 10

if curl -f http://localhost:8000/api/schema/ > /dev/null 2>&1; then
    show_success "Backend API funcionando"
else
    show_warning "Backend podría estar iniciando aún. Espere unos minutos."
fi

if curl -f http://localhost:3000 > /dev/null 2>&1; then
    show_success "Frontend funcionando"
else
    show_warning "Frontend podría estar iniciando aún. Espere unos minutos."
fi

echo ""
echo -e "${GREEN}¡Sistema listo para usar!${NC}"
echo "Acceda a http://localhost:3000 para comenzar"
echo ""
echo "Para detener el sistema: docker-compose down"
echo "Para ver logs en tiempo real: docker-compose logs -f"