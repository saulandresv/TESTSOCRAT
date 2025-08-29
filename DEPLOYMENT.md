# 🚀 Proyecto Sócrates - Guía de Deployment en Producción

## Sistema de Monitoreo SSL/TLS - Deployment Guide

Esta guía detalla cómo desplegar el Proyecto Sócrates en un entorno de producción seguro y escalable.

---

## 📋 Prerequisitos

### Servidor de Producción
- **OS**: Ubuntu 22.04 LTS o similar
- **RAM**: Mínimo 4GB, recomendado 8GB+
- **CPU**: Mínimo 2 cores, recomendado 4+ cores
- **Almacenamiento**: Mínimo 50GB SSD
- **Red**: Conexión estable a internet
- **Dominio**: Dominio configurado con DNS

### Software Requerido
```bash
# Docker y Docker Compose
sudo apt update
sudo apt install -y docker.io docker-compose-plugin
sudo systemctl enable docker
sudo usermod -aG docker $USER

# Herramientas SSL (para análisis)
sudo apt install -y nmap sslscan openssl dnsutils

# Nginx (si no se usa el contenedor)
sudo apt install -y nginx certbot python3-certbot-nginx

# Herramientas de monitoreo
sudo apt install -y htop iotop nethogs
```

---

## 🔧 Configuración Inicial

### 1. Preparar el Servidor

```bash
# Crear usuario para la aplicación
sudo useradd -m -s /bin/bash socrates
sudo usermod -aG docker socrates

# Crear directorios necesarios
sudo mkdir -p /opt/socrates/{logs,backups,ssl-certs,data}
sudo chown -R socrates:socrates /opt/socrates

# Configurar firewall
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable
```

### 2. Clonar y Configurar el Proyecto

```bash
# Cambiar al usuario socrates
sudo su - socrates

# Clonar el repositorio
cd /opt/socrates
git clone https://github.com/tu-usuario/Proyecto-Socrates.git
cd Proyecto-Socrates

# Crear archivo de configuración de producción
cp backend/production.env.example .env.production
```

### 3. Configurar Variables de Entorno

Editar `.env.production`:

```bash
# Configuración crítica de seguridad
SECRET_KEY=tu-clave-super-secreta-de-50-caracteres-aqui
DB_PASSWORD=password-mysql-muy-seguro
REDIS_PASSWORD=password-redis-muy-seguro
ADMIN_PASSWORD=password-admin-muy-seguro

# Configuración de dominio
ALLOWED_HOSTS=tu-dominio.com,api.tu-dominio.com
CORS_ALLOWED_ORIGINS=https://tu-dominio.com

# Email para notificaciones
EMAIL_HOST_USER=noreply@tu-dominio.com
EMAIL_HOST_PASSWORD=password-email
ADMIN_EMAIL=admin@tu-dominio.com

# Configuración de base de datos
DB_NAME=socrates_prod
DB_USER=socrates_user
DB_HOST=mysql
```

---

## 🔒 Certificados SSL

### Opción 1: Let's Encrypt (Recomendado)

```bash
# Instalar certbot
sudo apt install certbot

# Generar certificados
sudo certbot certonly --standalone \
  -d tu-dominio.com \
  -d api.tu-dominio.com \
  --email admin@tu-dominio.com \
  --agree-tos

# Copiar certificados al directorio del proyecto
sudo cp /etc/letsencrypt/live/tu-dominio.com/fullchain.pem /opt/socrates/ssl-certs/cert.pem
sudo cp /etc/letsencrypt/live/tu-dominio.com/privkey.pem /opt/socrates/ssl-certs/key.pem
sudo chown socrates:socrates /opt/socrates/ssl-certs/*

# Configurar renovación automática
echo "0 2 * * * certbot renew --quiet --post-hook 'docker-compose -f /opt/socrates/Proyecto-Socrates/docker-compose.prod.yml restart nginx'" | sudo crontab -
```

### Opción 2: Certificado Propio

```bash
# Generar certificado auto-firmado (solo para testing)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /opt/socrates/ssl-certs/key.pem \
  -out /opt/socrates/ssl-certs/cert.pem \
  -subj "/C=CL/ST=Santiago/L=Santiago/O=Tu-Empresa/CN=tu-dominio.com"
```

---

## 🐳 Deployment con Docker

### 1. Build y Deploy

```bash
cd /opt/socrates/Proyecto-Socrates

# Construir imágenes de producción
docker-compose -f docker-compose.prod.yml build

# Levantar servicios en background
docker-compose -f docker-compose.prod.yml up -d

# Verificar que todos los servicios estén corriendo
docker-compose -f docker-compose.prod.yml ps
```

### 2. Configuración Post-Deploy

```bash
# Verificar logs
docker-compose -f docker-compose.prod.yml logs -f backend

# Crear superusuario (si no se creó automáticamente)
docker-compose -f docker-compose.prod.yml exec backend python manage.py createsuperuser

# Cargar datos de ejemplo (opcional)
docker-compose -f docker-compose.prod.yml exec backend python manage.py seed_certificates --count 10

# Verificar herramientas SSL
docker-compose -f docker-compose.prod.yml exec backend nmap --version
docker-compose -f docker-compose.prod.yml exec backend sslscan --version
```

---

## 📊 Servicios Opcionales

### Monitoring con Prometheus + Grafana

```bash
# Activar perfil de monitoreo
docker-compose -f docker-compose.prod.yml --profile monitoring up -d

# Acceder a Grafana
# URL: https://tu-dominio.com:3001
# Usuario: admin
# Password: configurado en GRAFANA_PASSWORD
```

### Logging con ELK Stack

```bash
# Activar perfil de logging
docker-compose -f docker-compose.prod.yml --profile logging up -d

# Acceder a Kibana
# URL: https://tu-dominio.com:5601
```

### Backup Automático

```bash
# Activar servicio de backup
docker-compose -f docker-compose.prod.yml --profile backup up -d

# Backup manual
docker-compose -f docker-compose.prod.yml exec backup /backup-script.sh
```

---

## 🔧 Configuraciones Adicionales

### 1. Configurar Logrotate

```bash
sudo tee /etc/logrotate.d/socrates << EOF
/opt/socrates/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    sharedscripts
    postrotate
        docker-compose -f /opt/socrates/Proyecto-Socrates/docker-compose.prod.yml restart nginx
    endscript
}
EOF
```

### 2. Configurar Límites del Sistema

```bash
# Aumentar límites para Docker
sudo tee -a /etc/security/limits.conf << EOF
socrates soft nofile 65536
socrates hard nofile 65536
socrates soft nproc 32768
socrates hard nproc 32768
EOF

# Configurar kernel parameters
sudo tee -a /etc/sysctl.conf << EOF
# TCP tuning for high connections
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_tw_reuse = 1
EOF

sudo sysctl -p
```

### 3. Configurar Monitoreo de Sistema

```bash
# Script de monitoreo
sudo tee /opt/socrates/health-check.sh << 'EOF'
#!/bin/bash
cd /opt/socrates/Proyecto-Socrates

# Verificar servicios Docker
if ! docker-compose -f docker-compose.prod.yml ps | grep -q "Up"; then
    echo "ERROR: Algunos servicios Docker están caídos"
    docker-compose -f docker-compose.prod.yml up -d
fi

# Verificar respuesta HTTP
if ! curl -f -s https://tu-dominio.com/health/ > /dev/null; then
    echo "ERROR: La aplicación no responde"
    # Aquí podrías enviar una notificación
fi

# Verificar espacio en disco
DISK_USAGE=$(df / | awk 'NR==2 {print $5}' | cut -d'%' -f1)
if [ $DISK_USAGE -gt 80 ]; then
    echo "WARNING: Espacio en disco al ${DISK_USAGE}%"
fi
EOF

chmod +x /opt/socrates/health-check.sh

# Agregar a crontab
echo "*/5 * * * * /opt/socrates/health-check.sh >> /opt/socrates/logs/health.log 2>&1" | crontab -
```

---

## 🚨 Troubleshooting

### Problemas Comunes

**1. Error de Conexión a Base de Datos**
```bash
# Verificar que MySQL esté corriendo
docker-compose -f docker-compose.prod.yml logs mysql

# Resetear contraseña de MySQL
docker-compose -f docker-compose.prod.yml exec mysql mysql -u root -p -e "ALTER USER 'socrates_user'@'%' IDENTIFIED BY 'nueva-password';"
```

**2. Error de Permisos en Archivos**
```bash
# Corregir permisos
sudo chown -R socrates:socrates /opt/socrates
sudo chmod -R 755 /opt/socrates
sudo chmod 600 /opt/socrates/ssl-certs/*.pem
```

**3. Error de Memoria en Celery**
```bash
# Aumentar memoria para workers
docker-compose -f docker-compose.prod.yml exec celery_worker celery -A config worker --loglevel=info --concurrency=1
```

**4. Error de Rate Limiting**
```bash
# Ver logs de Nginx
docker-compose -f docker-compose.prod.yml logs nginx

# Ajustar rate limits en nginx.prod.conf si es necesario
```

### Comandos de Diagnóstico

```bash
# Estado general del sistema
docker-compose -f docker-compose.prod.yml ps
docker stats

# Logs específicos
docker-compose -f docker-compose.prod.yml logs -f backend
docker-compose -f docker-compose.prod.yml logs -f celery_worker

# Uso de recursos
htop
iotop
nethogs

# Verificar conectividad SSL
openssl s_client -connect tu-dominio.com:443 -servername tu-dominio.com
```

---

## 🔄 Actualizaciones

### Actualización de la Aplicación

```bash
cd /opt/socrates/Proyecto-Socrates

# Backup antes de actualizar
docker-compose -f docker-compose.prod.yml exec backup /backup-script.sh

# Pull de cambios
git pull origin main

# Rebuild y deploy
docker-compose -f docker-compose.prod.yml build
docker-compose -f docker-compose.prod.yml up -d

# Ejecutar migraciones si es necesario
docker-compose -f docker-compose.prod.yml exec backend python manage.py migrate
```

### Rolling Updates (Zero Downtime)

```bash
# Update backend sin downtime
docker-compose -f docker-compose.prod.yml up -d --no-deps backend

# Verificar health check
curl -f https://tu-dominio.com/health/

# Update workers
docker-compose -f docker-compose.prod.yml restart celery_worker celery_beat
```

---

## 📈 Escalabilidad

### Configuración para Alta Carga

```bash
# Múltiples workers de Celery
docker-compose -f docker-compose.prod.yml up -d --scale celery_worker=3

# Load balancer con Nginx (múltiples backends)
# Agregar más instancias de backend en nginx.conf:
# upstream backend {
#     server backend1:8000;
#     server backend2:8000;
#     server backend3:8000;
# }
```

### Base de Datos Master-Slave

```yaml
# Configurar en docker-compose.prod.yml
mysql_master:
  image: mysql:8.0
  environment:
    - MYSQL_REPLICATION_MODE=master
    
mysql_slave:
  image: mysql:8.0
  environment:
    - MYSQL_REPLICATION_MODE=slave
    - MYSQL_MASTER_HOST=mysql_master
```

---

## ✅ Checklist de Deployment

- [ ] Servidor preparado y configurado
- [ ] DNS apuntando al servidor
- [ ] Certificados SSL instalados
- [ ] Variables de entorno configuradas
- [ ] Firewall configurado
- [ ] Docker y servicios corriendo
- [ ] Health checks pasando
- [ ] Backups configurados
- [ ] Monitoreo activo
- [ ] Logs rotando correctamente
- [ ] Rate limiting configurado
- [ ] Notificaciones de email funcionando

---

## 🆘 Soporte

En caso de problemas:

1. **Revisar logs**: `docker-compose -f docker-compose.prod.yml logs`
2. **Verificar recursos**: `htop`, `df -h`
3. **Health checks**: `curl https://tu-dominio.com/health/`
4. **Contactar soporte**: admin@tu-dominio.com

¡El Proyecto Sócrates está listo para monitorear certificados SSL/TLS en producción! 🔒✨