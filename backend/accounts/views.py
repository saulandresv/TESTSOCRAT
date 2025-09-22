from rest_framework import status, permissions
from rest_framework.decorators import api_view, permission_classes
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
from .models import User
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
        
        return Response({
            'message': 'MFA configurado. Escanee el QR code con su app autenticator',
            'qr_code': f'data:image/png;base64,{img_base64}',
            'secret': secret,  # Para configuración manual
            'totp_uri': totp_uri
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

            # Verificar código con ventana de tiempo más amplia para setup (2 períodos = 60 segundos)
            is_valid = totp.verify(mfa_code, valid_window=2)

            if not is_valid:
                # Log del intento fallido para debug
                import logging
                logger = logging.getLogger(__name__)
                current_code = totp.now()
                logger.warning(f"MFA setup verification failed for user {user.email}. "
                             f"Provided: {mfa_code}, Expected: {current_code}")

                return Response({
                    'error': 'Código MFA inválido. Asegúrese de usar el código actual de su aplicación autenticadora.'
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
