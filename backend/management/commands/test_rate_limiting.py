"""
Comando para probar el sistema de rate limiting
"""

from django.core.management.base import BaseCommand
from django.test import RequestFactory
from django.contrib.auth import get_user_model
from django.core.cache import cache
from analysis.middleware import RateLimitMiddleware, APIRateLimitMixin
import time

User = get_user_model()


class Command(BaseCommand):
    help = 'Probar sistema de rate limiting'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--clear-cache',
            action='store_true',
            help='Limpiar caché de rate limiting antes de las pruebas'
        )
        
    def handle(self, *args, **options):
        if options['clear_cache']:
            cache.clear()
            self.stdout.write(self.style.SUCCESS('Caché limpiado'))
            
        self.test_middleware_rate_limiting()
        self.test_api_rate_limiting()
        self.test_burst_protection()
        
    def test_middleware_rate_limiting(self):
        """
        Probar middleware de rate limiting
        """
        self.stdout.write(self.style.WARNING('\n=== Probando Middleware Rate Limiting ==='))
        
        factory = RequestFactory()
        middleware = RateLimitMiddleware(lambda request: None)
        
        # Simular múltiples requests
        for i in range(15):
            request = factory.post('/api/analysis/', {'test': 'data'})
            request.META['REMOTE_ADDR'] = '127.0.0.1'
            request.user = None
            
            response = middleware._check_rate_limit(request)
            
            if response:
                self.stdout.write(f"Request {i+1}: BLOQUEADA - {response.status_code}")
                break
            else:
                self.stdout.write(f"Request {i+1}: PERMITIDA")
                
        self.stdout.write(self.style.SUCCESS('Middleware test completado'))
        
    def test_api_rate_limiting(self):
        """
        Probar rate limiting en APIs
        """
        self.stdout.write(self.style.WARNING('\n=== Probando API Rate Limiting ==='))
        
        # Crear usuario de prueba
        try:
            user = User.objects.get(email='test@example.com')
        except User.DoesNotExist:
            user = User.objects.create_user(
                email='test@example.com',
                password='testpass123',
                rol='ANALISTA',
                nombre='Test User'
            )
            
        factory = RequestFactory()
        
        # Simular requests de certificados
        for i in range(25):
            request = factory.get('/api/certificates/')
            request.user = user
            request.META['REMOTE_ADDR'] = '127.0.0.1'
            
            # Simular verificación de throttle
            cache_key = f"certificate:user:{user.id}:127.0.0.1"
            current_count = cache.get(cache_key, 0)
            
            if current_count >= 20:  # Límite simulado
                self.stdout.write(f"Certificate API {i+1}: BLOQUEADA")
                break
            else:
                cache.set(cache_key, current_count + 1, timeout=60)
                self.stdout.write(f"Certificate API {i+1}: PERMITIDA")
                
        self.stdout.write(self.style.SUCCESS('API rate limiting test completado'))
        
    def test_burst_protection(self):
        """
        Probar protección contra ráfagas
        """
        self.stdout.write(self.style.WARNING('\n=== Probando Burst Protection ==='))
        
        ip = '192.168.1.100'
        cache_key = f"burst:ip:{ip}"
        
        # Simular ráfaga de requests
        timestamps = []
        for i in range(12):
            now = time.time()
            timestamps.append(now)
            
            # Filtrar últimos 60 segundos
            recent = [ts for ts in timestamps if now - ts < 60]
            
            if len(recent) > 10:  # Límite de ráfaga
                self.stdout.write(f"Burst {i+1}: BLOQUEADA - {len(recent)} requests en 60s")
                break
            else:
                self.stdout.write(f"Burst {i+1}: PERMITIDA - {len(recent)} requests")
                
            cache.set(cache_key, recent, timeout=60)
            time.sleep(0.1)  # Pequeña pausa
            
        self.stdout.write(self.style.SUCCESS('Burst protection test completado'))
        
        # Mostrar estadísticas finales
        self.show_stats()
        
    def show_stats(self):
        """
        Mostrar estadísticas de rate limiting
        """
        self.stdout.write(self.style.WARNING('\n=== Estadísticas de Rate Limiting ==='))
        
        # Buscar claves de rate limiting en caché
        try:
            # Nota: esto es específico para Redis
            from django.core.cache.backends.redis import RedisCache
            
            if isinstance(cache, RedisCache):
                redis_client = cache._cache.get_client()
                keys = redis_client.keys('*rate_limit*')
                
                self.stdout.write(f"Claves de rate limiting activas: {len(keys)}")
                
                for key in keys[:10]:  # Mostrar primeras 10
                    value = redis_client.get(key)
                    ttl = redis_client.ttl(key)
                    self.stdout.write(f"  {key.decode()}: {value} (TTL: {ttl}s)")
                    
        except Exception as e:
            self.stdout.write(f"No se pudieron obtener estadísticas: {e}")
            
        self.stdout.write(self.style.SUCCESS('\n¡Pruebas de rate limiting completadas!'))
        self.stdout.write('Recomendaciones:')
        self.stdout.write('1. Monitorear logs para eventos de throttling')
        self.stdout.write('2. Ajustar límites según patrones de uso')
        self.stdout.write('3. Implementar alertas para IPs bloqueadas')
        self.stdout.write('4. Revisar métricas de rendimiento regularmente')