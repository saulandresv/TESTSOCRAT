from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle
from django.utils import timezone
from .models import Certificate, VitalityStatus
from .serializers import CertificateSerializer, CertificateCreateSerializer, VitalityStatusSerializer
from analysis.middleware import APIRateLimitMixin


class CertificatePermission(permissions.BasePermission):
    """
    Custom permission for certificate management based on user role.
    """
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        # Todos los roles autenticados pueden ver y gestionar certificados
        return request.user.rol in ['ADMIN', 'ANALISTA', 'CLIENT']


class CertificateThrottle(UserRateThrottle):
    scope = 'certificate'


class CertificateViewSet(APIRateLimitMixin, viewsets.ModelViewSet):
    """
    ViewSet para gestión de certificados con rate limiting
    """
    permission_classes = [CertificatePermission]
    throttle_classes = [CertificateThrottle]

    def create(self, request, *args, **kwargs):
        print(f"🔍 Certificate CREATE request from user: {request.user}")
        print(f"🔍 User role: {getattr(request.user, 'rol', 'NO_ROL')}")
        print(f"🔍 Request data: {request.data}")
        print(f"🔍 Request headers: {dict(request.headers)}")
        return super().create(request, *args, **kwargs)

    def get_queryset(self):
        user = self.request.user
        queryset = Certificate.objects.select_related('cliente').prefetch_related('vitality_checks')

        if user.rol == 'CLIENT':
            # Los clientes solo ven sus propios certificados
            client_ids = user.client_access.values_list('client_id', flat=True)
            queryset = queryset.filter(cliente_id__in=client_ids)
        # ADMIN y ANALISTA ven todos los certificados

        return queryset.filter(active=True)

    def get_serializer_class(self):
        if self.action == 'create':
            return CertificateCreateSerializer
        return CertificateSerializer
    
    @action(detail=True, methods=['post'])
    def check_vitality(self, request, pk=None):
        """
        Endpoint para verificar vitalidad manualmente
        """
        certificate = self.get_object()
        
        # Crear registro de vitalidad (simulado por ahora)
        vitality = VitalityStatus.objects.create(
            certificado=certificate,
            estado='activo'  # Por ahora siempre activo
        )
        
        return Response({
            'status': 'success',
            'vitality': VitalityStatusSerializer(vitality).data
        })


class VitalityStatusViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet de solo lectura para estados de vitalidad
    """
    queryset = VitalityStatus.objects.select_related('certificado')
    serializer_class = VitalityStatusSerializer
    permission_classes = [permissions.IsAuthenticated]
    throttle_classes = [UserRateThrottle]
