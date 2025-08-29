from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle
from django.utils import timezone
from .models import Certificate, VitalityStatus
from .serializers import CertificateSerializer, CertificateCreateSerializer, VitalityStatusSerializer
from analysis.middleware import APIRateLimitMixin


class IsAdminOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow admins to edit certificates.
    """
    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return True
        return bool(request.user and request.user.is_staff)


class CertificateThrottle(UserRateThrottle):
    scope = 'certificate'


class CertificateViewSet(APIRateLimitMixin, viewsets.ModelViewSet):
    """
    ViewSet para gestión de certificados con rate limiting
    """
    queryset = Certificate.objects.select_related('cliente').prefetch_related('vitality_checks')
    permission_classes = [IsAdminOrReadOnly]
    throttle_classes = [CertificateThrottle]
    
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
