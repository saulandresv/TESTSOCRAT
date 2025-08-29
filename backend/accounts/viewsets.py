from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from .models import User
from .serializers import UserSerializer, UserCreateSerializer, UserUpdateSerializer, ChangePasswordSerializer


class IsAdminOrOwner(permissions.BasePermission):
    """
    Permiso personalizado:
    - ADMIN puede ver/editar todos los usuarios
    - Usuarios pueden ver/editar solo su propio perfil
    """
    
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated
    
    def has_object_permission(self, request, view, obj):
        # ADMIN puede todo
        if request.user.rol == 'ADMIN':
            return True
        
        # Los usuarios solo pueden ver/editar su propio perfil
        return obj == request.user


class UserViewSet(viewsets.ModelViewSet):
    """
    ViewSet para gestión de usuarios
    Solo ADMIN puede crear/listar/eliminar usuarios
    Usuarios normales solo pueden ver/editar su perfil
    """
    queryset = User.objects.all()
    permission_classes = [IsAdminOrOwner]
    
    def get_serializer_class(self):
        if self.action == 'create':
            return UserCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return UserUpdateSerializer
        return UserSerializer
    
    def get_queryset(self):
        # ADMIN ve todos los usuarios
        if self.request.user.rol == 'ADMIN':
            return self.queryset.order_by('-date_joined')
        
        # Usuarios normales solo ven su propio perfil
        return self.queryset.filter(id=self.request.user.id)
    
    def list(self, request, *args, **kwargs):
        """Solo ADMIN puede listar usuarios"""
        if request.user.rol != 'ADMIN':
            return Response({
                'error': 'Solo administradores pueden listar usuarios'
            }, status=status.HTTP_403_FORBIDDEN)
        return super().list(request, *args, **kwargs)
    
    def create(self, request, *args, **kwargs):
        """Solo ADMIN puede crear usuarios"""
        if request.user.rol != 'ADMIN':
            return Response({
                'error': 'Solo administradores pueden crear usuarios'
            }, status=status.HTTP_403_FORBIDDEN)
        return super().create(request, *args, **kwargs)
    
    def destroy(self, request, *args, **kwargs):
        """Solo ADMIN puede eliminar usuarios"""
        if request.user.rol != 'ADMIN':
            return Response({
                'error': 'Solo administradores pueden eliminar usuarios'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # No permitir eliminar su propio usuario
        if self.get_object() == request.user:
            return Response({
                'error': 'No puedes eliminar tu propio usuario'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        return super().destroy(request, *args, **kwargs)
    
    @action(detail=True, methods=['post'])
    def change_password(self, request, pk=None):
        """
        Cambiar contraseña de usuario
        POST /api/v1/users/{id}/change_password/
        """
        user = self.get_object()
        
        # Solo el propio usuario puede cambiar su contraseña
        if user != request.user:
            return Response({
                'error': 'Solo puedes cambiar tu propia contraseña'
            }, status=status.HTTP_403_FORBIDDEN)
        
        serializer = ChangePasswordSerializer(
            data=request.data,
            context={'request': request}
        )
        
        if serializer.is_valid():
            user.set_password(serializer.validated_data['new_password'])
            user.save()
            
            return Response({
                'message': 'Contraseña cambiada exitosamente'
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=True, methods=['post'])
    def toggle_status(self, request, pk=None):
        """
        Activar/desactivar usuario (solo ADMIN)
        POST /api/v1/users/{id}/toggle_status/
        """
        if request.user.rol != 'ADMIN':
            return Response({
                'error': 'Solo administradores pueden cambiar el estado de usuarios'
            }, status=status.HTTP_403_FORBIDDEN)
        
        user = self.get_object()
        
        # No permitir desactivar su propio usuario
        if user == request.user and user.estado == 'activo':
            return Response({
                'error': 'No puedes desactivar tu propio usuario'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Alternar estado
        user.estado = 'inactivo' if user.estado == 'activo' else 'activo'
        user.save()
        
        return Response({
            'message': f'Usuario {user.estado}',
            'user': UserSerializer(user).data
        }, status=status.HTTP_200_OK)