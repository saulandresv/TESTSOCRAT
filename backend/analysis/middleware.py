"""
Middleware de Rate Limiting - Proyecto Sócrates
Sistema de Monitoreo SSL/TLS
"""

import logging
import time
from django.core.cache import cache
from django.http import JsonResponse
from django.conf import settings
from django.utils import timezone
from django.contrib.auth import get_user_model

logger = logging.getLogger(__name__)

User = get_user_model()


class RateLimitMiddleware:
    """
    Middleware personalizado para rate limiting basado en IP y usuario
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        
        # Configuraciones de rate limiting
        self.rate_limits = {
            # APIs críticas - límites más estrictos
            '/api/analysis/': {
                'requests': 10,
                'window': 60,  # 10 requests per minute
                'message': 'Demasiadas solicitudes de análisis. Intente más tarde.'
            },
            '/api/auth/login/': {
                'requests': 5,
                'window': 300,  # 5 attempts per 5 minutes
                'message': 'Demasiados intentos de login. Espere 5 minutos.'
            },
            '/api/certificates/create/': {
                'requests': 20,
                'window': 3600,  # 20 certificates per hour
                'message': 'Límite de certificados creados por hora alcanzado.'
            },
            # API general
            '/api/': {
                'requests': 100,
                'window': 3600,  # 100 requests per hour for general API
                'message': 'Límite de requests por hora alcanzado.'
            }
        }
        
    def __call__(self, request):
        # Aplicar rate limiting antes de procesar la request
        rate_limit_response = self._check_rate_limit(request)
        if rate_limit_response:
            return rate_limit_response
            
        response = self.get_response(request)
        return response
        
    def _check_rate_limit(self, request):
        """
        Verificar si la request excede los límites de rate limiting
        """
        path = request.path
        
        # Encontrar la regla de rate limiting más específica
        rate_limit_config = None
        matching_path = ""
        
        for pattern, config in self.rate_limits.items():
            if path.startswith(pattern) and len(pattern) > len(matching_path):
                rate_limit_config = config
                matching_path = pattern
                
        if not rate_limit_config:
            return None
            
        # Obtener identificador único (IP + usuario si está autenticado)
        identifier = self._get_client_identifier(request)
        cache_key = f"rate_limit:{matching_path}:{identifier}"
        
        # Obtener contador actual
        current_count = cache.get(cache_key, 0)
        
        if current_count >= rate_limit_config['requests']:
            # Límite excedido
            logger.warning(f"Rate limit exceeded for {identifier} on {path}")
            
            return JsonResponse({
                'error': 'Rate limit exceeded',
                'message': rate_limit_config['message'],
                'retry_after': rate_limit_config['window']
            }, status=429)
            
        # Incrementar contador
        cache.set(
            cache_key,
            current_count + 1,
            timeout=rate_limit_config['window']
        )
        
        return None
        
    def _get_client_identifier(self, request):
        """
        Obtener identificador único del cliente (IP + usuario)
        """
        # Obtener IP real considerando proxies
        ip = self._get_client_ip(request)
        
        # Si el usuario está autenticado, usar su ID
        if request.user and request.user.is_authenticated:
            return f"user:{request.user.id}:{ip}"
        
        return f"ip:{ip}"
        
    def _get_client_ip(self, request):
        """
        Obtener la IP real del cliente considerando proxies
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class APIRateLimitMixin:
    """
    Mixin para aplicar rate limiting específico en ViewSets de DRF
    """
    
    def dispatch(self, request, *args, **kwargs):
        """
        Aplicar rate limiting personalizado por acción
        """
        rate_limit_response = self._check_action_rate_limit(request)
        if rate_limit_response:
            return rate_limit_response
            
        return super().dispatch(request, *args, **kwargs)
        
    def _check_action_rate_limit(self, request):
        """
        Rate limiting específico por acción del ViewSet
        """
        action = getattr(self, 'action', None)
        if not action:
            return None
            
        # Configuraciones específicas por acción
        action_limits = {
            'create': {'requests': 10, 'window': 600},  # 10 creates per 10 minutes
            'bulk_create': {'requests': 2, 'window': 3600},  # 2 bulk operations per hour
            'destroy': {'requests': 20, 'window': 3600},  # 20 deletes per hour
        }
        
        if action not in action_limits:
            return None
            
        config = action_limits[action]
        identifier = self._get_client_identifier(request)
        cache_key = f"action_rate_limit:{self.__class__.__name__}:{action}:{identifier}"
        
        current_count = cache.get(cache_key, 0)
        
        if current_count >= config['requests']:
            logger.warning(f"Action rate limit exceeded: {identifier} - {action}")
            
            return JsonResponse({
                'error': f'Rate limit exceeded for action {action}',
                'message': f'Demasiadas operaciones de tipo {action}. Intente más tarde.',
                'retry_after': config['window']
            }, status=429)
            
        cache.set(cache_key, current_count + 1, timeout=config['window'])
        return None
        
    def _get_client_identifier(self, request):
        """
        Obtener identificador del cliente
        """
        ip = request.META.get('HTTP_X_FORWARDED_FOR', 
                             request.META.get('REMOTE_ADDR', 'unknown'))
        if request.user and request.user.is_authenticated:
            return f"user:{request.user.id}:{ip}"
        return f"ip:{ip}"


class SecurityRateLimitMiddleware:
    """
    Middleware de seguridad para detectar y bloquear comportamiento sospechoso
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):
        # Detectar patrones de ataque
        self._detect_attack_patterns(request)
        
        response = self.get_response(request)
        return response
        
    def _detect_attack_patterns(self, request):
        """
        Detectar patrones de ataque comunes
        """
        ip = self._get_client_ip(request)
        
        # Detectar SQL injection en parámetros
        suspicious_patterns = [
            'union select', 'drop table', 'insert into', 
            'delete from', '--', '/*', '*/'
        ]
        
        query_string = request.GET.urlencode().lower()
        for pattern in suspicious_patterns:
            if pattern in query_string:
                self._block_suspicious_ip(ip, f"SQL injection attempt: {pattern}")
                break
                
        # Detectar demasiadas requests 404
        if hasattr(request, 'resolver_match') and not request.resolver_match:
            self._track_404_attempts(ip)
            
    def _block_suspicious_ip(self, ip, reason):
        """
        Bloquear IP sospechosa temporalmente
        """
        cache_key = f"blocked_ip:{ip}"
        cache.set(cache_key, {
            'reason': reason,
            'timestamp': timezone.now().isoformat(),
            'blocked_until': (timezone.now() + timezone.timedelta(hours=1)).isoformat()
        }, timeout=3600)  # Block for 1 hour
        
        logger.warning(f"Blocked suspicious IP {ip}: {reason}")
        
    def _track_404_attempts(self, ip):
        """
        Rastrear intentos de acceso a URLs inexistentes
        """
        cache_key = f"404_attempts:{ip}"
        attempts = cache.get(cache_key, 0) + 1
        cache.set(cache_key, attempts, timeout=3600)
        
        if attempts > 20:  # More than 20 404s in an hour
            self._block_suspicious_ip(ip, f"Excessive 404 attempts: {attempts}")
            
    def _get_client_ip(self, request):
        """
        Obtener IP del cliente
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


def rate_limit_decorator(requests_per_minute=60):
    """
    Decorador para aplicar rate limiting a funciones específicas
    """
    def decorator(func):
        def wrapper(request, *args, **kwargs):
            # Implementar rate limiting
            identifier = f"ip:{request.META.get('REMOTE_ADDR', 'unknown')}"
            if hasattr(request, 'user') and request.user.is_authenticated:
                identifier = f"user:{request.user.id}"
                
            cache_key = f"func_rate_limit:{func.__name__}:{identifier}"
            current_count = cache.get(cache_key, 0)
            
            if current_count >= requests_per_minute:
                return JsonResponse({
                    'error': 'Rate limit exceeded',
                    'message': f'Máximo {requests_per_minute} requests por minuto para esta función.'
                }, status=429)
                
            cache.set(cache_key, current_count + 1, timeout=60)
            return func(request, *args, **kwargs)
            
        return wrapper
    return decorator