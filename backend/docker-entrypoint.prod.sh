#!/bin/bash
set -e

# Proyecto Sócrates - Production Docker Entrypoint
# Sistema de Monitoreo SSL/TLS

echo "🚀 Starting Proyecto Sócrates Production Setup..."

# Wait for MySQL to be ready
echo "⏳ Waiting for MySQL to be ready..."
while ! nc -z $DB_HOST $DB_PORT; do
  sleep 1
done
echo "✅ MySQL is ready!"

# Wait for Redis to be ready
echo "⏳ Waiting for Redis to be ready..."
while ! nc -z ${REDIS_HOST:-redis} ${REDIS_PORT:-6379}; do
  sleep 1
done
echo "✅ Redis is ready!"

# Set Django settings for production
export DJANGO_SETTINGS_MODULE=config.settings_prod

# Run database migrations
echo "🔄 Running database migrations..."
python manage.py migrate --noinput

# Create cache table (if using database cache)
echo "🔄 Creating cache tables..."
python manage.py createcachetable || true

# Collect static files
echo "📦 Collecting static files..."
python manage.py collectstatic --noinput --clear

# Create superuser if it doesn't exist
echo "👤 Setting up admin user..."
python manage.py shell -c "
from django.contrib.auth import get_user_model
import os
User = get_user_model()
admin_email = os.getenv('ADMIN_EMAIL', 'admin@socrates.com')
admin_password = os.getenv('ADMIN_PASSWORD', 'admin123')
if not User.objects.filter(email=admin_email).exists():
    User.objects.create_superuser(admin_email, admin_password)
    print(f'✅ Admin user created: {admin_email}')
else:
    print('ℹ️ Admin user already exists')
" || echo "⚠️ Could not create admin user"

# Setup periodic tasks for Celery Beat
echo "⏰ Setting up periodic tasks..."
python manage.py shell -c "
from django_celery_beat.models import PeriodicTask, CrontabSchedule
import json

# Create schedules if they don't exist
daily_schedule, created = CrontabSchedule.objects.get_or_create(
    minute=0,
    hour=2,
    day_of_week='*',
    day_of_month='*',
    month_of_year='*',
)

weekly_schedule, created = CrontabSchedule.objects.get_or_create(
    minute=0,
    hour=1,
    day_of_week=1,  # Monday
    day_of_month='*',
    month_of_year='*',
)

# Daily cleanup task
cleanup_task, created = PeriodicTask.objects.get_or_create(
    name='Daily SSL Analysis Cleanup',
    defaults={
        'crontab': daily_schedule,
        'task': 'analysis.tasks.cleanup_old_analyses',
        'args': json.dumps([]),
        'enabled': True,
    }
)

# Weekly certificate health check
health_task, created = PeriodicTask.objects.get_or_create(
    name='Weekly Certificate Health Check',
    defaults={
        'crontab': weekly_schedule,
        'task': 'certs.tasks.bulk_certificate_health_check',
        'args': json.dumps([]),
        'enabled': True,
    }
)

print('✅ Periodic tasks configured')
" || echo "⚠️ Could not setup periodic tasks"

# Verify SSL analysis tools are available
echo "🔧 Verifying SSL analysis tools..."
command -v nmap >/dev/null 2>&1 && echo "✅ nmap available" || echo "⚠️ nmap not found"
command -v sslscan >/dev/null 2>&1 && echo "✅ sslscan available" || echo "⚠️ sslscan not found"
command -v openssl >/dev/null 2>&1 && echo "✅ openssl available" || echo "⚠️ openssl not found"
python -c "import sslyze; print('✅ sslyze Python module available')" 2>/dev/null || echo "⚠️ sslyze module not available"

# Create log directory
mkdir -p /var/log/socrates

# Health check endpoint test
echo "🏥 Testing health check..."
python manage.py shell -c "
from django.test import Client
client = Client()
try:
    response = client.get('/health/')
    if response.status_code == 200:
        print('✅ Health check endpoint working')
    else:
        print(f'⚠️ Health check returned status {response.status_code}')
except Exception as e:
    print(f'⚠️ Health check failed: {e}')
" || echo "⚠️ Could not test health check"

echo "🎉 Production setup completed!"
echo "🔧 Starting application with: $@"

# Execute the main command
exec "$@"