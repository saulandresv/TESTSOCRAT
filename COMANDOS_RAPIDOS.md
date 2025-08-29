# ⚡ Comandos Rápidos - Proyecto Sócrates

## 🚀 Iniciar Desarrollo

```bash
# 1. Ir al proyecto
cd /mnt/c/Users/saulv/Desktop/i3g/proyecto-socrates

# 2. Revisar estado
cat DESARROLLO_FASE_1.md

# 3. Levantar Docker
cd infra/
docker-compose up -d

# 4. Ver containers
docker-compose ps

# 5. Entrar al backend
docker exec -it $(docker-compose ps -q backend) bash
```

## 🔧 Desarrollo Backend (dentro del container)

```bash
# Migraciones
python manage.py makemigrations
python manage.py migrate

# Crear apps
python manage.py startapp accounts
python manage.py startapp access

# Servidor
python manage.py runserver 0.0.0.0:8000

# Superuser
python manage.py createsuperuser

# Shell
python manage.py shell
```

## 📱 Frontend

```bash
# Desarrollo local
cd frontend/
npm install
npm run dev

# O con Docker
docker-compose up frontend
```

## 🐛 Debugging

```bash
# Logs
docker-compose logs backend
docker-compose logs mysql
docker-compose logs frontend

# Reiniciar servicio
docker-compose restart backend

# Entrar a MySQL
docker exec -it $(docker-compose ps -q mysql) mysql -u socrates -p socrates

# Ver archivos en container
docker exec -it backend_container ls -la
```

## 🔄 Estado Actual (Actualizar después de cada sesión)

**Última actualización:** 28 Ago 2025

- [ ] Docker containers funcionando
- [ ] Backend con clients app registrada
- [ ] Migraciones aplicadas
- [ ] Apps accounts y access creadas
- [ ] Modelos User y UserClientAccess
- [ ] APIs de autenticación
- [ ] Frontend conectado

**Próximo paso:** Revisar DESARROLLO_FASE_1.md y continuar desde el paso pendiente.