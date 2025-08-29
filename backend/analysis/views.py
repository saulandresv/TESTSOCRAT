from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle
from django.utils import timezone
from datetime import timedelta
from .models import Analysis, Vulnerabilidades
from .serializers import (
    AnalysisListSerializer, AnalysisDetailSerializer, 
    AnalysisCreateSerializer, VulnerabilidadesSerializer
)
from .analysis_engine import SSLAnalysisEngine
from .middleware import APIRateLimitMixin, rate_limit_decorator


class IsAdminOrAnalyst(permissions.BasePermission):
    """
    Permiso para ADMIN o ANALISTA
    """
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        return request.user.rol in ['ADMIN', 'ANALISTA']


class AnalysisThrottle(UserRateThrottle):
    scope = 'analysis'


class AnalysisViewSet(APIRateLimitMixin, viewsets.ModelViewSet):
    """
    ViewSet para gestión de análisis con rate limiting
    """
    queryset = Analysis.objects.select_related('certificado__cliente').prefetch_related(
        'vulnerabilidades', 'parametros_generales', 'parametros_tls'
    )
    permission_classes = [IsAdminOrAnalyst]
    throttle_classes = [AnalysisThrottle]
    
    def get_serializer_class(self):
        if self.action == 'list':
            return AnalysisListSerializer
        elif self.action == 'create':
            return AnalysisCreateSerializer
        return AnalysisDetailSerializer
    
    def get_queryset(self):
        queryset = self.queryset
        
        # Filtrar por certificado
        certificado = self.request.query_params.get('certificado', None)
        if certificado:
            queryset = queryset.filter(certificado_id=certificado)
        
        # Filtrar por cliente (si no es ADMIN)
        if self.request.user.rol != 'ADMIN':
            # ANALISTA solo ve análisis de certificados de sus clientes asignados
            client_ids = self.request.user.client_access.values_list('client_id', flat=True)
            queryset = queryset.filter(certificado__cliente_id__in=client_ids)
        
        # Filtrar por tipo de análisis
        tipo = self.request.query_params.get('tipo', None)
        if tipo:
            queryset = queryset.filter(tipo=tipo)
        
        # Filtrar por éxito/fallo
        success = self.request.query_params.get('success', None)
        if success is not None:
            queryset = queryset.filter(tuvo_exito=success.lower() == 'true')
        
        # Filtrar por rango de fechas
        date_from = self.request.query_params.get('date_from', None)
        date_to = self.request.query_params.get('date_to', None)
        
        if date_from:
            queryset = queryset.filter(fecha_inicio__gte=date_from)
        if date_to:
            queryset = queryset.filter(fecha_inicio__lte=date_to)
        
        return queryset.order_by('-fecha_inicio')
    
    @action(detail=False, methods=['post'])
    def run_analysis(self, request):
        """
        Ejecutar análisis manual
        POST /api/analysis/run_analysis/
        Body: {"certificate_ids": [1, 2, 3], "tipo": "SSL_TLS"}
        """
        certificate_ids = request.data.get('certificate_ids', [])
        tipo = request.data.get('tipo', 'SSL_TLS')
        
        if not certificate_ids:
            return Response({
                'error': 'certificate_ids requerido'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Obtener certificados
        from certs.models import Certificate
        certificates = Certificate.objects.filter(
            id__in=certificate_ids,
            active=True
        )
        
        if not certificates.exists():
            return Response({
                'error': 'No se encontraron certificados válidos'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Crear análisis y ejecutar
        results = []
        engine = SSLAnalysisEngine()
        
        for cert in certificates:
            # Crear registro de análisis
            analysis = Analysis.objects.create(
                certificado=cert,
                tipo=tipo,
                triggered_by='MANUAL',
                comentarios=f'Análisis manual ejecutado por {request.user.email}'
            )
            
            # Ejecutar análisis (asíncrono en producción)
            try:
                success = engine.analyze_certificate(analysis)
                analysis.tuvo_exito = success
                analysis.fecha_fin = timezone.now()
                analysis.save()
                
                results.append({
                    'certificate_id': cert.id,
                    'analysis_id': analysis.id,
                    'success': success,
                    'target': cert.ip or cert.url
                })
            except Exception as e:
                analysis.tuvo_exito = False
                analysis.error_message = str(e)
                analysis.fecha_fin = timezone.now()
                analysis.save()
                
                results.append({
                    'certificate_id': cert.id,
                    'analysis_id': analysis.id,
                    'success': False,
                    'error': str(e)
                })
        
        return Response({
            'message': f'Análisis ejecutado en {len(results)} certificados',
            'results': results
        }, status=status.HTTP_200_OK)
    
    @action(detail=False, methods=['get'])
    def dashboard_stats(self, request):
        """
        Estadísticas para dashboard
        GET /api/analysis/dashboard_stats/
        """
        # Últimos 30 días
        since = timezone.now() - timedelta(days=30)
        queryset = self.get_queryset().filter(fecha_inicio__gte=since)
        
        stats = {
            'total_analyses': queryset.count(),
            'successful': queryset.filter(tuvo_exito=True).count(),
            'failed': queryset.filter(tuvo_exito=False).count(),
            'by_type': {},
            'recent_vulnerabilities': {
                'critical': 0,
                'high': 0,
                'total': 0
            }
        }
        
        # Por tipo de análisis
        for analysis_type in ['SSL_TLS', 'SSH', 'WEB', 'FULL']:
            count = queryset.filter(tipo=analysis_type).count()
            if count > 0:
                stats['by_type'][analysis_type] = count
        
        # Vulnerabilidades recientes
        recent_vulns = Vulnerabilidades.objects.filter(
            analisis__in=queryset.filter(tuvo_exito=True)
        )
        stats['recent_vulnerabilities'] = {
            'total': recent_vulns.count(),
            'critical': recent_vulns.filter(severity='CRITICAL').count(),
            'high': recent_vulns.filter(severity='HIGH').count(),
            'medium': recent_vulns.filter(severity='MEDIUM').count(),
            'low': recent_vulns.filter(severity='LOW').count(),
        }
        
        return Response(stats, status=status.HTTP_200_OK)
    
    @action(detail=True, methods=['get'])
    def vulnerabilities(self, request, pk=None):
        """
        Obtener vulnerabilidades de un análisis específico
        GET /api/analysis/{id}/vulnerabilities/
        """
        analysis = self.get_object()
        vulnerabilities = analysis.vulnerabilidades.all()
        serializer = VulnerabilidadesSerializer(vulnerabilities, many=True)
        
        return Response({
            'analysis_id': analysis.id,
            'certificate': str(analysis.certificado),
            'vulnerabilities': serializer.data,
            'summary': {
                'total': vulnerabilities.count(),
                'by_severity': {
                    'critical': vulnerabilities.filter(severity='CRITICAL').count(),
                    'high': vulnerabilities.filter(severity='HIGH').count(),
                    'medium': vulnerabilities.filter(severity='MEDIUM').count(),
                    'low': vulnerabilities.filter(severity='LOW').count(),
                }
            }
        }, status=status.HTTP_200_OK)
