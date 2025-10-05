from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from .models import Client
from .serializers import ClientSerializer
import logging

logger = logging.getLogger(__name__)

class IsAdminOrAnalyst(permissions.BasePermission):
    """
    Permiso para ADMIN (puede modificar) o ANALISTA (solo lectura)
    Usuarios CLIENT solo ven sus clientes asignados
    """
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            logger.warning(f"Permission denied: User not authenticated")
            return False

        user_role = request.user.rol
        logger.info(f"Permission check - User: {request.user.email}, Role: {user_role}")

        # ADMIN tiene acceso completo
        if user_role == 'ADMIN':
            return True

        # ANALISTA solo lectura
        if user_role == 'ANALISTA':
            return request.method in permissions.SAFE_METHODS

        # CLIENT solo lectura y filtrado por sus clientes
        if user_role == 'CLIENT':
            return request.method in permissions.SAFE_METHODS

        return False

class ClientViewSet(viewsets.ModelViewSet):
    serializer_class = ClientSerializer
    permission_classes = [IsAdminOrAnalyst]

    def get_queryset(self):
        user = self.request.user
        logger.info(f"ClientViewSet.get_queryset - User: {user.email}, Role: {user.rol}")

        # ADMIN ve todos los clientes
        if user.rol == 'ADMIN':
            return Client.objects.all()

        # ANALISTA ve todos los clientes (solo lectura)
        elif user.rol == 'ANALISTA':
            return Client.objects.all()

        # CLIENT solo ve clientes a los que tiene acceso
        elif user.rol == 'CLIENT':
            client_ids = user.client_access.values_list('client_id', flat=True)
            logger.info(f"CLIENT user has access to clients: {list(client_ids)}")
            return Client.objects.filter(id__in=client_ids)

        # Por defecto, sin acceso
        return Client.objects.none()

    def destroy(self, request, *args, **kwargs):
        """
        No permitir eliminación física, solo deshabilitar
        """
        return Response(
            {'error': 'Los clientes no se pueden eliminar, solo deshabilitar. Use toggle_status.'},
            status=status.HTTP_400_BAD_REQUEST
        )

    @action(detail=True, methods=['patch'])
    def toggle_status(self, request, pk=None):
        """
        Cambiar estado activo/inactivo del cliente
        """
        if request.user.rol != 'ADMIN':
            return Response(
                {'error': 'Solo administradores pueden cambiar el estado'},
                status=status.HTTP_403_FORBIDDEN
            )

        try:
            client = self.get_object()
            new_status = 'inactivo' if client.status == 'activo' else 'activo'
            client.status = new_status
            client.save()

            serializer = self.get_serializer(client)
            logger.info(f"Client {client.name} status changed to {new_status}")

            return Response({
                'message': f'Cliente {client.name} marcado como {new_status}',
                'client': serializer.data
            })

        except Exception as e:
            logger.error(f"Error changing client status: {e}")
            return Response(
                {'error': 'Error al cambiar estado del cliente'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
