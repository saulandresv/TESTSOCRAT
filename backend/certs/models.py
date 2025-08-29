from django.db import models
from django.utils import timezone


class Certificate(models.Model):
    """
    Modelo Certificate según esquema BDD
    Tabla: certificados
    """
    cliente = models.ForeignKey('clients.Client', on_delete=models.CASCADE, related_name='certificados')
    nombre_certificado = models.CharField(max_length=255, blank=True, null=True)
    ip = models.GenericIPAddressField(blank=True, null=True)
    url = models.URLField(max_length=500, blank=True, null=True)
    puerto = models.PositiveIntegerField()
    protocolo = models.CharField(max_length=20, choices=[
        ('HTTPS', 'HTTPS'),
        ('TLS', 'TLS'),
        ('SSH', 'SSH'),
        ('SMTP', 'SMTP'),
        ('IMAP', 'IMAP'),
        ('POP3', 'POP3'),
        ('FTP', 'FTP'),
        ('OTHER', 'Other')
    ])
    frecuencia_analisis = models.PositiveSmallIntegerField(
        default=30,
        help_text="Días entre análisis automáticos"
    )
    fecha_proxima_revision = models.DateTimeField(default=timezone.now)
    fecha_expiracion = models.DateField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'certificados'
        constraints = [
            models.UniqueConstraint(
                fields=['ip', 'puerto'],
                condition=models.Q(ip__isnull=False),
                name='unique_ip_puerto'
            ),
            models.UniqueConstraint(
                fields=['url', 'puerto'],
                condition=models.Q(url__isnull=False),
                name='unique_url_puerto'
            ),
        ]
        indexes = [
            models.Index(fields=['cliente', 'active']),
            models.Index(fields=['fecha_proxima_revision']),
            models.Index(fields=['protocolo']),
        ]
    
    def clean(self):
        from django.core.exceptions import ValidationError
        if not self.ip and not self.url:
            raise ValidationError('Debe especificar IP o URL')
        if self.ip and self.url:
            raise ValidationError('Especifique solo IP o URL, no ambos')
    
    def __str__(self):
        target = self.ip or self.url
        return f"{target}:{self.puerto} ({self.protocolo})"


class VitalityStatus(models.Model):
    """
    Modelo VitalityStatus según esquema BDD  
    Tabla: estado_vitalidad
    """
    certificado = models.ForeignKey(
        Certificate, 
        on_delete=models.CASCADE, 
        related_name='vitality_checks'
    )
    hora = models.DateTimeField(auto_now_add=True)
    estado = models.CharField(max_length=20, choices=[
        ('activo', 'Activo/Up'),
        ('inactivo', 'Inactivo/Down')
    ])
    response_time_ms = models.PositiveIntegerField(null=True, blank=True)
    error_message = models.TextField(blank=True)
    
    class Meta:
        db_table = 'estado_vitalidad'
        indexes = [
            models.Index(fields=['certificado', 'hora']),
            models.Index(fields=['estado']),
        ]
        ordering = ['-hora']
    
    def __str__(self):
        return f"{self.certificado} - {self.estado} ({self.hora})"
