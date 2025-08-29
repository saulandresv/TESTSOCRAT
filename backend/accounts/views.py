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
        
        # Si tiene MFA habilitado, requerir código
        if user.token_mfa:
            return Response({
                'mfa_required': True,
                'message': 'Ingrese código MFA',
                'user_id': user.id
            }, status=status.HTTP_200_OK)
        
        # Sin MFA, generar tokens directamente
        refresh = RefreshToken.for_user(user)
        user.ultimo_login = timezone.now()
        user.save()
        
        return Response({
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'user': UserSerializer(user).data,
            'message': 'Login exitoso'
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
        
        if not user.token_mfa:
            return Response({
                'error': 'MFA no configurado para este usuario'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Verificar código TOTP
        totp = pyotp.TOTP(user.token_mfa)
        if not totp.verify(mfa_code):
            return Response({
                'error': 'Código MFA inválido'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
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
    
    def delete(self, request):
        """Deshabilitar MFA"""
        user = request.user
        user.token_mfa = None
        user.save()
        
        return Response({
            'message': 'MFA deshabilitado'
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
