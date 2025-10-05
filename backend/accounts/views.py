from rest_framework import status, permissions, viewsets
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.utils import timezone
import pyotp
import qrcode
import io
import base64
from .models import User, UserClientAccess
from .serializers import UserSerializer


class LoginThrottle(AnonRateThrottle):
    scope = 'login'


class LoginView(APIView):
    """
    POST /api/v1/auth/login
    Login con email/password, retorna JWT o requiere MFA
    """
    permission_classes = [permissions.AllowAny]
    throttle_classes = [LoginThrottle]
    
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        
        if not email or not password:
            return Response({
                'error': 'Email y password requeridos'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Autenticar usuario
        user = authenticate(request, username=email, password=password)
        if not user:
            return Response({
                'error': 'Credenciales inválidas'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        if user.estado != 'activo':
            return Response({
                'error': 'Usuario inactivo'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # MFA OBLIGATORIO: Verificar que el usuario tenga MFA configurado
        if not user.token_mfa or not user.mfa_enabled:
            return Response({
                'mfa_setup_required': True,
                'error': 'MFA es obligatorio para todos los usuarios. Configure MFA desde su perfil.',
                'message': 'Debe configurar autenticación de dos factores antes de continuar',
                'user_id': user.id
            }, status=status.HTTP_403_FORBIDDEN)

        # Si tiene MFA habilitado, requerir código
        return Response({
            'mfa_required': True,
            'message': 'Ingrese código MFA',
            'user_id': user.id
        }, status=status.HTTP_200_OK)


class MFAVerifyView(APIView):
    """
    POST /api/v1/auth/mfa/verify
    Verificar código TOTP y generar JWT
    """
    permission_classes = [permissions.AllowAny]
    throttle_classes = [LoginThrottle]
    
    def post(self, request):
        user_id = request.data.get('user_id')
        mfa_code = request.data.get('mfa_code')
        
        if not user_id or not mfa_code:
            return Response({
                'error': 'user_id y mfa_code requeridos'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({
                'error': 'Usuario no encontrado'
            }, status=status.HTTP_404_NOT_FOUND)
        
        if not user.token_mfa or not user.mfa_enabled:
            return Response({
                'error': 'MFA no configurado o no habilitado para este usuario'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Verificar código TOTP con validación estricta
        try:
            # Convertir a string y limpiar espacios
            mfa_code = str(mfa_code).strip()

            # Verificar que sea un código de 6 dígitos
            if not mfa_code.isdigit() or len(mfa_code) != 6:
                return Response({
                    'error': 'Código MFA debe ser de 6 dígitos numéricos'
                }, status=status.HTTP_400_BAD_REQUEST)

            totp = pyotp.TOTP(user.token_mfa)

            # Verificar código actual y permitir una ventana de 30 segundos antes/después
            is_valid = totp.verify(mfa_code, valid_window=1)

            if not is_valid:
                # Log del intento fallido para debug
                import logging
                logger = logging.getLogger(__name__)
                current_code = totp.now()
                logger.warning(f"MFA verification failed for user {user.email}. "
                             f"Provided: {mfa_code}, Expected: {current_code}")

                return Response({
                    'error': 'Código MFA inválido'
                }, status=status.HTTP_401_UNAUTHORIZED)

        except Exception as e:
            return Response({
                'error': 'Error al verificar código MFA'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        # Generar tokens JWT
        refresh = RefreshToken.for_user(user)
        user.ultimo_login = timezone.now()
        user.save()
        
        return Response({
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'user': UserSerializer(user).data,
            'message': 'Login MFA exitoso'
        }, status=status.HTTP_200_OK)


class MFASetupView(APIView):
    """
    POST /api/v1/auth/mfa/setup
    Configurar MFA para usuario autenticado, generar QR code
    """
    permission_classes = [permissions.IsAuthenticated]
    throttle_classes = [UserRateThrottle]
    
    def post(self, request):
        user = request.user
        
        # Generar secret TOTP
        secret = pyotp.random_base32()
        
        # Guardar secret (temporalmente)
        user.token_mfa = secret
        user.save()
        
        # Generar QR code
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            user.email,
            issuer_name="Proyecto Sócrates"
        )
        
        # Crear imagen QR
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        # Convertir a base64
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        img_base64 = base64.b64encode(buffer.getvalue()).decode()
        
        # Generar código actual para verificación
        current_totp = pyotp.TOTP(secret)
        current_code = current_totp.now()

        return Response({
            'message': 'MFA configurado. Escanee el QR code con su app autenticator',
            'qr_code': f'data:image/png;base64,{img_base64}',
            'secret': secret,  # Para configuración manual
            'totp_uri': totp_uri,
            'current_code': current_code,  # Para verificación inmediata
            'setup_info': {
                'time_window': '150 segundos',
                'tip': 'Después de escanear, espere hasta que aparezca un código nuevo'
            }
        }, status=status.HTTP_200_OK)
    
    def put(self, request):
        """Confirmar y habilitar MFA tras verificar código TOTP"""
        user = request.user
        mfa_code = request.data.get('mfa_code')

        if not mfa_code:
            return Response({
                'error': 'Código MFA requerido'
            }, status=status.HTTP_400_BAD_REQUEST)

        if not user.token_mfa:
            return Response({
                'error': 'No hay configuración MFA pendiente'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Verificar código TOTP con validación estricta
        try:
            # Convertir a string y limpiar espacios
            mfa_code = str(mfa_code).strip()

            # Verificar que sea un código de 6 dígitos
            if not mfa_code.isdigit() or len(mfa_code) != 6:
                return Response({
                    'error': 'Código MFA debe ser de 6 dígitos numéricos'
                }, status=status.HTTP_400_BAD_REQUEST)

            totp = pyotp.TOTP(user.token_mfa)

            # Verificar código con ventana de tiempo más amplia para setup (5 períodos = 150 segundos)
            is_valid = totp.verify(mfa_code, valid_window=5)

            if not is_valid:
                # Log del intento fallido para debug
                import logging
                import time
                logger = logging.getLogger(__name__)
                current_code = totp.now()

                # Mostrar códigos en ventana de tiempo
                current_time = int(time.time())
                codes_window = []
                for i in range(-2, 3):  # -60s a +60s
                    code_at_time = totp.at(current_time + (i * 30))
                    codes_window.append(f"{i*30}s: {code_at_time}")

                logger.warning(f"MFA setup verification failed for user {user.email}. "
                             f"Provided: {mfa_code}, Current: {current_code}. "
                             f"Valid codes in window: {', '.join(codes_window)}")

                return Response({
                    'error': 'Código MFA inválido. Asegúrese de usar el código actual de su aplicación autenticadora.',
                    'debug_info': {
                        'provided_code': mfa_code,
                        'current_expected': current_code,
                        'time_window': '150 segundos (±2.5 minutos)',
                        'tip': 'Verifique que la hora en su dispositivo esté sincronizada'
                    }
                }, status=status.HTTP_401_UNAUTHORIZED)

        except Exception as e:
            return Response({
                'error': 'Error al verificar código MFA'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Habilitar MFA definitivamente
        user.mfa_enabled = True
        user.save()

        return Response({
            'message': 'MFA habilitado exitosamente',
            'mfa_enabled': True
        }, status=status.HTTP_200_OK)

    def delete(self, request):
        """Deshabilitar MFA - SOLO PARA TESTING, NO USAR EN PRODUCCIÓN"""
        user = request.user
        user.token_mfa = None
        user.mfa_enabled = False
        user.save()

        return Response({
            'message': 'MFA deshabilitado'
        }, status=status.HTTP_200_OK)


class MFASetupLoginView(APIView):
    """
    POST /api/v1/auth/mfa/setup-login
    Login especial para usuarios sin MFA que necesitan configurarlo
    """
    permission_classes = [permissions.AllowAny]
    throttle_classes = [LoginThrottle]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return Response({
                'error': 'Email y password requeridos'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Autenticar usuario
        user = authenticate(request, username=email, password=password)
        if not user:
            return Response({
                'error': 'Credenciales inválidas'
            }, status=status.HTTP_401_UNAUTHORIZED)

        if user.estado != 'activo':
            return Response({
                'error': 'Usuario inactivo'
            }, status=status.HTTP_403_FORBIDDEN)

        # Solo permitir si el usuario NO tiene MFA configurado
        if user.token_mfa and user.mfa_enabled:
            return Response({
                'error': 'Usuario ya tiene MFA configurado. Use login normal.'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Generar token temporal para configurar MFA (15 minutos)
        refresh = RefreshToken.for_user(user)
        access_token = refresh.access_token
        access_token.set_exp(lifetime=timezone.timedelta(minutes=15))

        return Response({
            'access': str(access_token),
            'temp_token': True,
            'message': 'Token temporal para configurar MFA',
            'user': {
                'id': user.id,
                'email': user.email,
                'nombre_usuario': user.nombre_usuario,
                'rol': user.rol,
                'mfa_enabled': user.mfa_enabled
            }
        }, status=status.HTTP_200_OK)


class UserProfileView(APIView):
    """
    GET /api/v1/auth/profile
    Obtener perfil del usuario autenticado
    """
    permission_classes = [permissions.IsAuthenticated]
    throttle_classes = [UserRateThrottle]
    
    def get(self, request):
        return Response({
            'user': UserSerializer(request.user).data
        }, status=status.HTTP_200_OK)


class IsAdminOnly(permissions.BasePermission):
    """Solo ADMIN puede gestionar usuarios"""
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.rol == 'ADMIN'


class UserViewSet(viewsets.ModelViewSet):
    """ViewSet para gestión de usuarios con control de acceso"""
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAdminOnly]

    def destroy(self, request, *args, **kwargs):
        """No permitir eliminación física de usuarios"""
        return Response(
            {'error': 'Los usuarios no se pueden eliminar, solo deshabilitar.'},
            status=status.HTTP_400_BAD_REQUEST
        )

    @action(detail=True, methods=['patch'])
    def toggle_status(self, request, pk=None):
        """Activar/desactivar usuario"""
        try:
            user = self.get_object()
            new_status = 'inactivo' if user.estado == 'activo' else 'activo'
            user.estado = new_status
            user.save()
            
            return Response({
                'message': f'Usuario {user.email} marcado como {new_status}',
                'user': UserSerializer(user).data
            })
        except User.DoesNotExist:
            return Response({'error': 'Usuario no encontrado'}, status=404)

    @action(detail=False, methods=['post'])
    def assign_client_access(self, request):
        """Asignar acceso de usuario a cliente"""
        user_id = request.data.get('user_id')
        client_id = request.data.get('client_id')
        
        if not user_id or not client_id:
            return Response({
                'error': 'user_id y client_id requeridos'
            }, status=400)
        
        try:
            from clients.models import Client
            user = User.objects.get(id=user_id)
            client = Client.objects.get(id=client_id)
            
            access, created = UserClientAccess.objects.get_or_create(
                user=user, 
                client=client
            )
            
            if created:
                return Response({
                    'message': f'Acceso otorgado a {user.email} para cliente {client.name}'
                })
            else:
                return Response({
                    'message': f'{user.email} ya tiene acceso a {client.name}'
                })
                
        except (User.DoesNotExist, Client.DoesNotExist):
            return Response({'error': 'Usuario o cliente no encontrado'}, status=404)

    @action(detail=False, methods=['delete'])
    def remove_client_access(self, request):
        """Remover acceso de usuario a cliente"""
        user_id = request.data.get('user_id')
        client_id = request.data.get('client_id')
        
        try:
            access = UserClientAccess.objects.get(user_id=user_id, client_id=client_id)
            access.delete()
            
            return Response({
                'message': 'Acceso removido exitosamente'
            })
        except UserClientAccess.DoesNotExist:
            return Response({'error': 'Acceso no encontrado'}, status=404)
