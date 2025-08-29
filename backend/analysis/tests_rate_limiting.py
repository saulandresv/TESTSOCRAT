"""
Tests para Rate Limiting - Proyecto Sócrates
"""

import time
from unittest.mock import patch, MagicMock
from django.test import TestCase, RequestFactory
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.http import JsonResponse
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from analysis.middleware import (
    RateLimitMiddleware, APIRateLimitMixin,
    SecurityRateLimitMiddleware, rate_limit_decorator
)

User = get_user_model()


class RateLimitMiddlewareTest(TestCase):
    """
    Tests para el middleware de rate limiting
    """
    
    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = RateLimitMiddleware(lambda request: None)
        cache.clear()
        
    def test_rate_limit_anonymous_user(self):
        """
        Probar rate limiting para usuarios anónimos
        """
        # Simular múltiples requests desde la misma IP
        for i in range(12):  # Exceder límite de análisis (10/min)
            request = self.factory.post('/api/analysis/', {'test': 'data'})
            request.META['REMOTE_ADDR'] = '192.168.1.1'
            request.user = None
            
            response = self.middleware._check_rate_limit(request)
            
            if i >= 10:  # A partir del 11vo request
                self.assertIsNotNone(response)
                self.assertEqual(response.status_code, 429)
            else:
                self.assertIsNone(response)
                
    def test_rate_limit_authenticated_user(self):
        """
        Probar rate limiting para usuarios autenticados
        """
        user = User.objects.create_user(
            email='test@example.com',
            password='testpass',
            rol='ANALISTA'
        )
        
        # Usuarios autenticados deberían tener límites más altos
        for i in range(15):
            request = self.factory.post('/api/analysis/', {'test': 'data'})
            request.META['REMOTE_ADDR'] = '192.168.1.2'
            request.user = user
            
            response = self.middleware._check_rate_limit(request)
            
            # Los primeros 10 deberían pasar
            if i < 10:
                self.assertIsNone(response)
                
    def test_different_endpoints_different_limits(self):
        """
        Probar que diferentes endpoints tienen diferentes límites
        """
        # Login tiene límite más estricto
        for i in range(6):
            request = self.factory.post('/api/auth/login/', {'email': 'test@test.com'})
            request.META['REMOTE_ADDR'] = '192.168.1.3'
            request.user = None
            
            response = self.middleware._check_rate_limit(request)
            
            if i >= 5:  # Login limitado a 5/5min
                self.assertIsNotNone(response)
                self.assertEqual(response.status_code, 429)
            else:
                self.assertIsNone(response)
                
    def test_client_identifier_generation(self):
        """
        Probar generación de identificadores de cliente
        """
        # Usuario anónimo
        request = self.factory.get('/api/test/')
        request.META['REMOTE_ADDR'] = '192.168.1.4'
        request.user = None
        
        identifier = self.middleware._get_client_identifier(request)
        self.assertTrue(identifier.startswith('ip:'))
        
        # Usuario autenticado
        user = User.objects.create_user(
            email='test2@example.com',
            password='testpass',
            rol='ADMIN'
        )
        request.user = user
        
        identifier = self.middleware._get_client_identifier(request)
        self.assertTrue(identifier.startswith('user:'))
        self.assertIn(str(user.id), identifier)


class SecurityMiddlewareTest(TestCase):
    """
    Tests para middleware de seguridad
    """
    
    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = SecurityRateLimitMiddleware(lambda request: None)
        cache.clear()
        
    def test_sql_injection_detection(self):
        """
        Probar detección de patrones de SQL injection
        """
        request = self.factory.get('/api/test/?id=1 UNION SELECT * FROM users--')
        request.META['REMOTE_ADDR'] = '192.168.1.100'
        
        with patch.object(self.middleware, '_block_suspicious_ip') as mock_block:
            self.middleware._detect_attack_patterns(request)
            mock_block.assert_called_once()
            
    def test_suspicious_url_detection(self):
        """
        Probar detección de URLs sospechosas
        """
        suspicious_paths = [
            '/admin/config.php',
            '/.env',
            '/wp-admin/admin.php',
            '/phpmyadmin/index.php'
        ]
        
        for path in suspicious_paths:
            request = self.factory.get(path)
            request.META['REMOTE_ADDR'] = '192.168.1.101'
            
            with patch.object(self.middleware, '_block_suspicious_ip') as mock_block:
                self.middleware._detect_attack_patterns(request)
                # Deberían detectarse como sospechosos los paths de admin externos
                if any(pattern in path for pattern in ['/admin', '/.env', '/wp-admin']):
                    mock_block.assert_called()
                    
    def test_404_tracking(self):
        """
        Probar seguimiento de intentos 404 excesivos
        """
        ip = '192.168.1.102'
        
        # Simular múltiples 404s
        for i in range(25):
            self.middleware._track_404_attempts(ip)
            
        # Después de 20 intentos, debería bloquear
        cache_key = f"blocked_ip:{ip}"
        blocked_info = cache.get(cache_key)
        self.assertIsNotNone(blocked_info)
        self.assertIn('404 attempts', blocked_info['reason'])


class APIRateLimitMixinTest(TestCase):
    """
    Tests para el mixin de rate limiting en APIs
    """
    
    def setUp(self):
        self.factory = RequestFactory()
        cache.clear()
        
        # Crear clase de prueba que usa el mixin
        class TestViewSet(APIRateLimitMixin):
            action = 'create'
            
        self.viewset = TestViewSet()
        
    def test_action_rate_limiting(self):
        """
        Probar rate limiting por acción
        """
        user = User.objects.create_user(
            email='test3@example.com',
            password='testpass',
            rol='ANALISTA'
        )
        
        # Simular múltiples operaciones de create
        for i in range(12):
            request = self.factory.post('/api/test/')
            request.META['REMOTE_ADDR'] = '192.168.1.5'
            request.user = user
            
            response = self.viewset._check_action_rate_limit(request)
            
            if i >= 10:  # Límite de create: 10 por 10 minutos
                self.assertIsNotNone(response)
                self.assertEqual(response.status_code, 429)
            else:
                self.assertIsNone(response)


class RateLimitDecoratorTest(TestCase):
    """
    Tests para el decorador de rate limiting
    """
    
    def setUp(self):
        self.factory = RequestFactory()
        cache.clear()
        
    def test_function_rate_limiting(self):
        """
        Probar rate limiting en funciones decoradas
        """
        @rate_limit_decorator(requests_per_minute=3)
        def test_function(request):
            return JsonResponse({'status': 'ok'})
            
        user = User.objects.create_user(
            email='test4@example.com',
            password='testpass',
            rol='ADMIN'
        )
        
        # Probar múltiples llamadas
        for i in range(5):
            request = self.factory.get('/test/')
            request.user = user
            request.META['REMOTE_ADDR'] = '192.168.1.6'
            
            response = test_function(request)
            
            if i >= 3:  # Límite: 3 por minuto
                self.assertEqual(response.status_code, 429)
                self.assertIn('Rate limit exceeded', response.content.decode())
            else:
                self.assertEqual(response.status_code, 200)


class APIEndpointRateLimitTest(APITestCase):
    """
    Tests de integración para rate limiting en endpoints reales
    """
    
    def setUp(self):
        self.client = APIClient()
        cache.clear()
        
        # Crear usuario de prueba
        self.user = User.objects.create_user(
            email='api_test@example.com',
            password='testpass123',
            rol='ANALISTA'
        )
        
    def test_login_rate_limiting(self):
        """
        Probar rate limiting en endpoint de login
        """
        login_data = {
            'email': 'wrong@example.com',
            'password': 'wrongpass'
        }
        
        # Intentar login múltiples veces
        blocked = False
        for i in range(10):
            response = self.client.post('/api/auth/login/', login_data)
            
            if response.status_code == 429:
                blocked = True
                break
                
        # Debería haberse bloqueado antes del intento 10
        self.assertTrue(blocked, "Login debería haberse bloqueado por rate limiting")
        
    @patch('analysis.views.SSLAnalysisEngine')
    def test_analysis_rate_limiting(self, mock_engine):
        """
        Probar rate limiting en endpoint de análisis
        """
        # Autenticar usuario
        self.client.force_authenticate(user=self.user)
        
        # Mock del engine de análisis
        mock_engine.return_value.analyze_certificate.return_value = True
        
        # Crear certificado de prueba
        from certs.models import Certificate
        from clients.models import Cliente
        
        client = Cliente.objects.create(
            name='Test Client',
            email='client@test.com'
        )
        
        cert = Certificate.objects.create(
            cliente=client,
            url='test.example.com',
            puerto=443,
            protocolo='HTTPS'
        )
        
        analysis_data = {
            'certificate_ids': [cert.id],
            'tipo': 'SSL_TLS'
        }
        
        # Intentar múltiples análisis
        blocked = False
        for i in range(25):
            response = self.client.post('/api/analysis/run_analysis/', analysis_data)
            
            if response.status_code == 429:
                blocked = True
                self.assertIn('rate limit', response.data.get('error', '').lower())
                break
                
        # El rate limiting debería haberse aplicado
        self.assertTrue(blocked, "Analysis endpoint debería haberse bloqueado")
        
    def test_certificate_creation_rate_limiting(self):
        """
        Probar rate limiting en creación de certificados
        """
        self.client.force_authenticate(user=self.user)
        
        # Crear cliente
        from clients.models import Cliente
        client = Cliente.objects.create(
            name='Test Client 2',
            email='client2@test.com'
        )
        
        cert_data = {
            'cliente': client.id,
            'url': 'example.com',
            'puerto': 443,
            'protocolo': 'HTTPS'
        }
        
        # Intentar crear muchos certificados
        success_count = 0
        blocked = False
        
        for i in range(25):
            cert_data['url'] = f'example{i}.com'  # URL única
            response = self.client.post('/api/certificates/', cert_data)
            
            if response.status_code == 429:
                blocked = True
                break
            elif response.status_code == 201:
                success_count += 1
                
        # Debería haberse bloqueado eventualmente
        self.assertTrue(blocked or success_count < 25, 
                       "Certificate creation debería tener rate limiting")


class CachePerformanceTest(TestCase):
    """
    Tests de rendimiento para el sistema de caché
    """
    
    def setUp(self):
        cache.clear()
        
    def test_cache_performance(self):
        """
        Probar rendimiento del caché con múltiples operaciones
        """
        start_time = time.time()
        
        # Realizar múltiples operaciones de caché
        for i in range(1000):
            cache.set(f"test_key_{i}", f"test_value_{i}", timeout=60)
            cache.get(f"test_key_{i}")
            
        end_time = time.time()
        duration = end_time - start_time
        
        # Debería completarse en menos de 1 segundo
        self.assertLess(duration, 1.0, 
                       f"Cache operations took {duration:.2f}s, should be < 1s")
        
    def test_memory_usage(self):
        """
        Probar uso de memoria con muchas claves
        """
        # Crear muchas claves de rate limiting
        keys_created = 0
        for i in range(10000):
            try:
                cache.set(f"rate_limit_test_{i}", i, timeout=3600)
                keys_created += 1
            except Exception:
                break
                
        # Debería poder crear al menos 1000 claves
        self.assertGreater(keys_created, 1000, 
                          "Should be able to create many cache keys")
                          
        # Limpiar
        for i in range(keys_created):
            cache.delete(f"rate_limit_test_{i}")