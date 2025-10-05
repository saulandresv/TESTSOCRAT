from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
import pyotp
import qrcode
import io
import base64

class User(AbstractUser):
    # Usar email como identificador principal
    email = models.EmailField(unique=True)
    
    # Campos específicos del proyecto
    nombre_usuario = models.CharField(max_length=100)
    rol = models.CharField(
        max_length=20,
        choices=[
            ('ADMIN', 'Admin'),
            ('CLIENT', 'Cliente'),
            ('ANALISTA', 'Analista')
        ],
        default='CLIENT'
    )
    estado = models.CharField(
        max_length=20,
        choices=[
            ('activo', 'Activo'),
            ('inactivo', 'Inactivo')
        ],
        default='activo'
    )
    
    # MFA fields (según esquema BDD)
    token_mfa = models.CharField(max_length=32, blank=True, null=True)  # secret TOTP
    mfa_enabled = models.BooleanField(default=False)
    ultimo_login = models.DateTimeField(null=True, blank=True)  # sobrescribir default
    
    # Configuración para usar email como login
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['nombre_usuario']  # Removemos username ya que usamos email
    
    def __str__(self):
        return f'{self.email} ({self.rol})'
    
    def save(self, *args, **kwargs):
        # Actualizar ultimo_login automáticamente
        if not self.pk:  # nuevo usuario
            self.ultimo_login = timezone.now()
        super().save(*args, **kwargs)
    
    def generate_mfa_secret(self):
        """Generar nuevo secreto TOTP"""
        self.token_mfa = pyotp.random_base32()
        return self.token_mfa
    
    def get_totp_uri(self):
        """Obtener URI para QR code"""
        if not self.token_mfa:
            self.generate_mfa_secret()
            self.save()
        
        return pyotp.totp.TOTP(self.token_mfa).provisioning_uri(
            name=self.email,
            issuer_name="Proyecto Sócrates"
        )
    
    def get_qr_code_base64(self):
        """Generar QR code como imagen base64"""
        uri = self.get_totp_uri()
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        img_str = base64.b64encode(buffer.getvalue()).decode()
        return f"data:image/png;base64,{img_str}"
    
    def verify_totp(self, token):
        """Verificar token TOTP"""
        if not self.token_mfa or not self.mfa_enabled:
            return False
        
        totp = pyotp.TOTP(self.token_mfa)
        return totp.verify(token)
    
    def enable_mfa(self):
        """Habilitar MFA"""
        self.mfa_enabled = True
        self.save()
    
    def disable_mfa(self):
        """Deshabilitar MFA"""
        self.mfa_enabled = False
        self.token_mfa = None
        self.save()
    
    class Meta:
        verbose_name = 'Usuario'
        verbose_name_plural = 'Usuarios'
        db_table = 'usuarios'  # usar nombre de tabla según esquema BDD


class UserClientAccess(models.Model):
    """
    Modelo para manejar acceso de usuarios a múltiples clientes
    Un usuario puede tener acceso a varios clientes
    """
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='client_access'
    )
    client = models.ForeignKey(
        'clients.Client',  # Forward reference para evitar import circular
        on_delete=models.CASCADE,
        related_name='user_access'
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'client')  # Un usuario no puede tener acceso duplicado al mismo cliente
        verbose_name = 'Acceso Usuario-Cliente'
        verbose_name_plural = 'Accesos Usuario-Cliente'
        db_table = 'user_client_access'

    def __str__(self):
        return f'{self.user.email} -> {self.client.name}'