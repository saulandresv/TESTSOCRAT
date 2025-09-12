"""
Views para generación y gestión de reportes - Proyecto Sócrates
Sistema de Monitoreo SSL/TLS
"""

import os
import json
from datetime import datetime, timedelta
from django.http import HttpResponse, JsonResponse, FileResponse, Http404
from django.utils import timezone
from django.shortcuts import get_object_or_404
from django.conf import settings
from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle

from .models import Report
from .serializers import ReportSerializer, ReportCreateSerializer
from .tasks import generate_report_async, send_report_via_email
from clients.models import Client


class ReportsRateThrottle(UserRateThrottle):
    scope = 'reports'


class ReportViewSet(viewsets.ModelViewSet):
    """
    ViewSet para gestión de reportes según especificaciones Proyecto Sócrates
    """
    queryset = Report.objects.all().select_related('client')
    serializer_class = ReportSerializer
    permission_classes = [permissions.IsAuthenticated]
    throttle_classes = [ReportsRateThrottle]
    
    def get_serializer_class(self):
        if self.action == 'create':
            return ReportCreateSerializer
        return ReportSerializer
    
    def get_queryset(self):
        """Filtrar reportes según permisos del usuario"""
        queryset = self.queryset
        
        # Si no es ADMIN, filtrar por clientes asignados
        if hasattr(self.request.user, 'rol') and self.request.user.rol != 'ADMIN':
            client_ids = self.request.user.client_access.values_list('client_id', flat=True)
            queryset = queryset.filter(client_id__in=client_ids)
        
        # Filtros adicionales
        client_id = self.request.query_params.get('client', None)
        if client_id:
            queryset = queryset.filter(client_id=client_id)
            
        report_type = self.request.query_params.get('type', None)
        if report_type:
            queryset = queryset.filter(report_type=report_type)
            
        status_filter = self.request.query_params.get('status', None)
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        return queryset.order_by('-created_at')
    
    def create(self, request):
        """
        Crear nuevo reporte según especificaciones Proyecto Sócrates
        
        POST /api/reports/
        {
            "client_id": 1,
            "report_type": "CERTIFICATE_DETAILED",
            "format": "PDF",
            "filters": {
                "date_from": "2024-01-01",
                "date_to": "2024-12-31",
                "protocolo": "HTTPS"
            },
            "description": "Reporte mensual de certificados SSL"
        }
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Crear reporte
        report = serializer.save()
        
        # Iniciar generación asíncrona
        task_result = generate_report_async.delay(report.id)
        
        return Response({
            'report_id': str(report.id),
            'task_id': task_result.id,
            'status': 'QUEUED',
            'message': 'Reporte en cola para generación',
            'estimated_time': self._estimate_generation_time(report)
        }, status=status.HTTP_201_CREATED)
    
    @action(detail=True, methods=['get'])
    def download(self, request, pk=None):
        """
        Descargar archivo de reporte generado
        
        GET /api/reports/{id}/download/
        """
        report = self.get_object()
        
        if report.status != 'COMPLETED':
            return Response({
                'error': 'Reporte no completado',
                'status': report.status
            }, status=status.HTTP_400_BAD_REQUEST)
            
        if not report.file_path or not os.path.exists(report.file_path):
            return Response({
                'error': 'Archivo de reporte no encontrado'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Preparar respuesta de descarga
        filename = f"Reporte_{report.client.name}_{report.created_at.strftime('%Y%m%d')}.{report.format.lower()}"
        
        # Determinar content type
        content_type = {
            'PDF': 'application/pdf',
            'EXCEL': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'JSON': 'application/json'
        }.get(report.format, 'application/octet-stream')
        
        try:
            response = FileResponse(
                open(report.file_path, 'rb'),
                content_type=content_type,
                as_attachment=True,
                filename=filename
            )
            
            return response
            
        except FileNotFoundError:
            raise Http404("Archivo no encontrado")
    
    @action(detail=True, methods=['post'])
    def send_email(self, request, pk=None):
        """
        Enviar reporte por email según especificaciones Proyecto Sócrates
        
        POST /api/reports/{id}/send_email/
        {
            "recipients": ["admin@company.com", "analyst@company.com"],
            "include_summary": true
        }
        """
        report = self.get_object()
        
        recipients = request.data.get('recipients', [])
        include_summary = request.data.get('include_summary', True)
        
        if not recipients:
            return Response({
                'error': 'Lista de destinatarios requerida'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if report.status != 'COMPLETED':
            return Response({
                'error': 'Reporte debe estar completado para enviar por email',
                'status': report.status
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Enviar email asíncronamente
        task_result = send_report_via_email.delay(
            report.id, 
            recipients, 
            include_summary
        )
        
        return Response({
            'message': 'Email programado para envío',
            'task_id': task_result.id,
            'recipients': recipients
        }, status=status.HTTP_200_OK)
    
    @action(detail=False, methods=['get'])
    def stats(self, request):
        """
        Estadísticas de reportes generados
        
        GET /api/reports/stats/
        """
        queryset = self.get_queryset()
        
        # Estadísticas últimos 30 días
        last_30_days = timezone.now() - timedelta(days=30)
        recent_reports = queryset.filter(created_at__gte=last_30_days)
        
        stats = {
            'total_reports': queryset.count(),
            'recent_reports': recent_reports.count(),
            'by_status': {
                'completed': recent_reports.filter(status='COMPLETED').count(),
                'processing': recent_reports.filter(status='PROCESSING').count(),
                'queued': recent_reports.filter(status='QUEUED').count(),
                'failed': recent_reports.filter(status='FAILED').count(),
            },
            'by_type': {
                'detailed': recent_reports.filter(report_type='CERTIFICATE_DETAILED').count(),
                'overview': recent_reports.filter(report_type='CLIENT_OVERVIEW').count(),
                'expiration': recent_reports.filter(report_type='EXPIRATION_ALERT').count(),
            },
            'by_format': {
                'pdf': recent_reports.filter(format='PDF').count(),
                'excel': recent_reports.filter(format='EXCEL').count(),
                'json': recent_reports.filter(format='JSON').count(),
            },
            'total_file_size_mb': sum(
                report.file_size_mb for report in recent_reports.filter(status='COMPLETED') 
                if report.file_size_mb
            )
        }
        
        return Response(stats, status=status.HTTP_200_OK)
    
    @action(detail=False, methods=['post'])
    def bulk_generate(self, request):
        """
        Generar reportes masivos para múltiples clientes
        
        POST /api/reports/bulk_generate/
        {
            "client_ids": [1, 2, 3],
            "report_type": "CERTIFICATE_DETAILED",
            "format": "PDF",
            "filters": {...}
        }
        """
        client_ids = request.data.get('client_ids', [])
        report_type = request.data.get('report_type', 'CERTIFICATE_DETAILED')
        format_type = request.data.get('format', 'PDF')
        filters = request.data.get('filters', {})
        description = request.data.get('description', 'Reporte masivo')
        
        if not client_ids:
            return Response({
                'error': 'Lista de client_ids requerida'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Validar clientes
        clients = Client.objects.filter(id__in=client_ids)
        if not clients.exists():
            return Response({
                'error': 'No se encontraron clientes válidos'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Crear reportes para cada cliente
        reports_created = []
        
        for client in clients:
            try:
                report = Report.objects.create(
                    client=client,
                    report_type=report_type,
                    format=format_type,
                    filters=filters,
                    description=f"{description} - {client.name}"
                )
                
                # Iniciar generación
                task_result = generate_report_async.delay(report.id)
                
                reports_created.append({
                    'client_id': client.id,
                    'client_name': client.name,
                    'report_id': str(report.id),
                    'task_id': task_result.id,
                    'status': 'queued'
                })
                
            except Exception as e:
                reports_created.append({
                    'client_id': client.id,
                    'client_name': client.name,
                    'error': str(e),
                    'status': 'failed'
                })
        
        return Response({
            'message': f'Generación masiva iniciada para {len(clients)} clientes',
            'reports_created': len([r for r in reports_created if 'report_id' in r]),
            'errors': len([r for r in reports_created if 'error' in r]),
            'details': reports_created
        }, status=status.HTTP_201_CREATED)
    
    def _estimate_generation_time(self, report):
        """
        Estimar tiempo de generación basado en tipo y formato
        """
        base_times = {
            'CERTIFICATE_DETAILED': {
                'PDF': '2-5 minutos',
                'EXCEL': '1-3 minutos',
                'JSON': '30 segundos'
            },
            'CLIENT_OVERVIEW': {
                'PDF': '1-2 minutos',
                'EXCEL': '1-2 minutos',
                'JSON': '15 segundos'
            },
            'EXPIRATION_ALERT': {
                'PDF': '1 minuto',
                'EXCEL': '30 segundos',
                'JSON': '10 segundos'
            }
        }
        
        return base_times.get(report.report_type, {}).get(report.format, '1-2 minutos')


class ReportTemplatesView:
    """
    Vista para templates y ejemplos de reportes
    """
    
    @staticmethod
    def get_report_templates():
        """
        Obtener templates disponibles según especificaciones
        """
        templates = {
            'certificate_detailed': {
                'name': 'Reporte Detallado de Certificados',
                'description': 'Incluye todos los parámetros especificados en Proyecto Sócrates',
                'sections': [
                    'A) Parámetros Generales del Certificado',
                    'B) Evaluación de Protocolos y Cifradores SSL/TLS',
                    'C) Vulnerabilidades Conocidas',
                    'D) Validación e Integridad de la Cadena de Certificación',
                    'E) Parámetros Específicos para SSH',
                    'F) Parámetros adicionales para APIs y Web',
                    'G) Otros parámetros Útiles'
                ],
                'formats': ['PDF', 'EXCEL', 'JSON'],
                'estimated_pages': '5-15 páginas por certificado'
            },
            'client_overview': {
                'name': 'Resumen por Cliente',
                'description': 'Vista consolidada de todos los certificados del cliente',
                'sections': [
                    'Resumen ejecutivo',
                    'Estado de certificados',
                    'Alertas de expiración',
                    'Métricas de seguridad'
                ],
                'formats': ['PDF', 'EXCEL'],
                'estimated_pages': '2-5 páginas'
            },
            'expiration_alert': {
                'name': 'Alerta de Expiración',
                'description': 'Certificados próximos a expirar según especificaciones',
                'sections': [
                    'Certificados críticos (7 días)',
                    'Certificados de advertencia (30 días)',
                    'Recomendaciones de renovación'
                ],
                'formats': ['PDF', 'JSON'],
                'estimated_pages': '1-2 páginas'
            }
        }
        
        return templates


def get_report_templates(request):
    """
    API endpoint para obtener templates de reportes disponibles
    
    GET /api/reports/templates/
    """
    if request.method == 'GET':
        templates = ReportTemplatesView.get_report_templates()
        return JsonResponse({
            'templates': templates,
            'specifications_compliance': 'Proyecto Sócrates v1.0',
            'supported_formats': ['PDF', 'EXCEL', 'JSON'],
            'max_certificates_per_report': 100
        })
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)