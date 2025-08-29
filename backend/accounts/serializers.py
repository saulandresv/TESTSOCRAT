from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from .models import User


class UserSerializer(serializers.ModelSerializer):
    """
    Serializer para User (lectura)
    """
    mfa_enabled = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = [
            'id', 'email', 'nombre_usuario', 'rol', 'estado', 
            'ultimo_login', 'date_joined', 'is_staff', 'is_superuser',
            'mfa_enabled'
        ]
        read_only_fields = [
            'id', 'ultimo_login', 'date_joined', 'is_staff', 'is_superuser'
        ]
    
    def get_mfa_enabled(self, obj):
        """Indica si el usuario tiene MFA habilitado"""
        return bool(obj.token_mfa)


class UserCreateSerializer(serializers.ModelSerializer):
    """
    Serializer para crear usuarios
    """
    password = serializers.CharField(write_only=True, validators=[validate_password])
    password_confirm = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = [
            'email', 'nombre_usuario', 'rol', 'estado',
            'password', 'password_confirm'
        ]
    
    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Las contraseñas no coinciden")
        return attrs
    
    def create(self, validated_data):
        # Remover password_confirm
        validated_data.pop('password_confirm', None)
        
        # Crear usuario
        user = User.objects.create_user(
            username=validated_data['email'],  # Django requiere username
            email=validated_data['email'],
            password=validated_data['password'],
            nombre_usuario=validated_data['nombre_usuario'],
            rol=validated_data.get('rol', 'CLIENTE'),
            estado=validated_data.get('estado', 'activo')
        )
        return user


class UserUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer para actualizar usuarios
    """
    
    class Meta:
        model = User
        fields = ['nombre_usuario', 'rol', 'estado']
    
    def validate_estado(self, value):
        """No permitir que un usuario se desactive a sí mismo"""
        if (self.instance and 
            self.instance == self.context.get('request').user and 
            value == 'inactivo'):
            raise serializers.ValidationError(
                "No puedes desactivar tu propio usuario"
            )
        return value


class ChangePasswordSerializer(serializers.Serializer):
    """
    Serializer para cambiar contraseña
    """
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, validators=[validate_password])
    new_password_confirm = serializers.CharField(required=True)
    
    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError("Las contraseñas nuevas no coinciden")
        return attrs
    
    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Contraseña actual incorrecta")
        return value


# Serializers para MFA
class MFASetupSerializer(serializers.Serializer):
    """
    Serializer para iniciar configuración MFA
    """
    password = serializers.CharField(required=True)
    
    def validate_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Contraseña incorrecta")
        return value


class MFAVerifySetupSerializer(serializers.Serializer):
    """
    Serializer para verificar y completar configuración MFA
    """
    token = serializers.CharField(required=True, min_length=6, max_length=6)
    
    def validate_token(self, value):
        if not value.isdigit():
            raise serializers.ValidationError("El token debe ser numérico")
        return value


class MFAVerifySerializer(serializers.Serializer):
    """
    Serializer para verificar token MFA durante login
    """
    email = serializers.EmailField(required=True)
    token = serializers.CharField(required=True, min_length=6, max_length=6)
    
    def validate_token(self, value):
        if not value.isdigit():
            raise serializers.ValidationError("El token debe ser numérico")
        return value


class LoginSerializer(serializers.Serializer):
    """
    Serializer para login inicial
    """
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True)


class MFADisableSerializer(serializers.Serializer):
    """
    Serializer para deshabilitar MFA
    """
    password = serializers.CharField(required=True)
    token = serializers.CharField(required=True, min_length=6, max_length=6)
    
    def validate_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Contraseña incorrecta")
        return value
    
    def validate_token(self, value):
        if not value.isdigit():
            raise serializers.ValidationError("El token debe ser numérico")
        return value