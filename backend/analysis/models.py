from django.db import models
from django.utils import timezone


class Analysis(models.Model):
    """
    Tabla: analisis
    Análisis realizados a certificados
    """
    certificado = models.ForeignKey(
        'certs.Certificate', 
        on_delete=models.CASCADE, 
        related_name='analyses'
    )
    tipo = models.CharField(max_length=50, choices=[
        ('SSL_TLS', 'SSL/TLS Analysis'),
        ('SSH', 'SSH Analysis'),
        ('WEB', 'Web Security Analysis'),
        ('FULL', 'Full Analysis'),
    ])
    tuvo_exito = models.BooleanField(default=False)
    fecha_inicio = models.DateTimeField(default=timezone.now)
    fecha_fin = models.DateTimeField(null=True, blank=True)
    comentarios = models.TextField(blank=True)
    
    # Campos adicionales para tracking
    triggered_by = models.CharField(max_length=20, choices=[
        ('MANUAL', 'Manual'),
        ('SCHEDULED', 'Programado'),
        ('API', 'API Call')
    ], default='MANUAL')
    error_message = models.TextField(blank=True)
    
    class Meta:
        db_table = 'analisis'
        ordering = ['-fecha_inicio']
        indexes = [
            models.Index(fields=['certificado', 'tuvo_exito']),
            models.Index(fields=['tipo', 'fecha_inicio']),
        ]
    
    def __str__(self):
        return f"Analysis {self.tipo} - {self.certificado} ({self.fecha_inicio})"


class ParametrosGenerales(models.Model):
    """
    Tabla: parametros_generales
    Parámetros generales del certificado SSL
    """
    analisis = models.OneToOneField(
        Analysis, 
        on_delete=models.CASCADE, 
        related_name='parametros_generales'
    )
    common_name = models.CharField(max_length=255, blank=True)
    san = models.TextField(blank=True, help_text="Subject Alternative Names (JSON)")
    issuer = models.CharField(max_length=255, blank=True)
    subject = models.CharField(max_length=255, blank=True)
    serial_number = models.CharField(max_length=255, blank=True)
    version = models.CharField(max_length=10, blank=True)
    algoritmo_firma = models.CharField(max_length=100, blank=True)
    key_size = models.IntegerField(null=True, blank=True)
    key_algorithm = models.CharField(max_length=50, blank=True)
    fecha_inicio = models.DateField(null=True, blank=True)
    fecha_fin = models.DateField(null=True, blank=True)
    dias_restantes = models.IntegerField(null=True, blank=True)
    estado_revocacion = models.CharField(max_length=50, blank=True)
    
    class Meta:
        db_table = 'parametros_generales'
    
    def __str__(self):
        return f"General Params - {self.common_name}"


class ParametrosTLS(models.Model):
    """
    Tabla: parametros_tls  
    Parámetros específicos de TLS/SSL
    """
    analisis = models.OneToOneField(
        Analysis,
        on_delete=models.CASCADE,
        related_name='parametros_tls'
    )
    protocolos = models.TextField(blank=True, help_text="Protocolos soportados (JSON)")
    cifrados_disponibles = models.TextField(blank=True, help_text="Lista de cifrados (JSON)")
    cifrados_debiles = models.TextField(blank=True, help_text="Cifrados débiles encontrados (JSON)")
    pfs = models.BooleanField(null=True, help_text="Perfect Forward Secrecy")
    
    # Campos adicionales importantes
    sslv2_supported = models.BooleanField(null=True)
    sslv3_supported = models.BooleanField(null=True)
    tls10_supported = models.BooleanField(null=True)
    tls11_supported = models.BooleanField(null=True)
    tls12_supported = models.BooleanField(null=True)
    tls13_supported = models.BooleanField(null=True)
    
    class Meta:
        db_table = 'parametros_tls'
    
    def __str__(self):
        return f"TLS Params - Analysis {self.analisis.id}"


class Vulnerabilidades(models.Model):
    """
    Tabla: vulnerabilidades
    Vulnerabilidades detectadas
    """
    analisis = models.ForeignKey(
        Analysis,
        on_delete=models.CASCADE,
        related_name='vulnerabilidades'
    )
    vulnerabilidad = models.CharField(max_length=255)
    severity = models.CharField(max_length=20, choices=[
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'), 
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical')
    ], default='LOW')
    description = models.TextField(blank=True)
    
    # Vulnerabilidades comunes
    VULN_CHOICES = [
        ('HEARTBLEED', 'Heartbleed'),
        ('POODLE', 'POODLE'),
        ('DROWN', 'DROWN'),
        ('BEAST', 'BEAST'),
        ('CRIME', 'CRIME'),
        ('BREACH', 'BREACH'),
        ('LOGJAM', 'Logjam'),
        ('FREAK', 'FREAK'),
        ('WEAK_CIPHER', 'Weak Cipher'),
        ('EXPIRED_CERT', 'Expired Certificate'),
        ('SELF_SIGNED', 'Self-signed Certificate'),
        ('OTHER', 'Other')
    ]
    
    class Meta:
        db_table = 'vulnerabilidades'
        indexes = [
            models.Index(fields=['analisis', 'severity']),
        ]
    
    def __str__(self):
        return f"{self.vulnerabilidad} - {self.severity}"


class CadenaCertificacion(models.Model):
    """
    Tabla: cadena_certificacion
    Estado de la cadena de certificación
    """
    analisis = models.OneToOneField(
        Analysis,
        on_delete=models.CASCADE,
        related_name='cadena_certificacion'
    )
    cadena_ok = models.BooleanField(default=False)
    errores = models.BooleanField(default=False)
    autofirmado = models.BooleanField(default=False)
    intermedios_extra = models.BooleanField(default=False)
    
    # Detalles adicionales
    chain_length = models.IntegerField(null=True, blank=True)
    root_ca = models.CharField(max_length=255, blank=True)
    intermediate_cas = models.TextField(blank=True, help_text="CAs intermedias (JSON)")
    validation_errors = models.TextField(blank=True)
    
    class Meta:
        db_table = 'cadena_certificacion'
    
    def __str__(self):
        status = "OK" if self.cadena_ok else "ERROR"
        return f"Chain Status: {status} - Analysis {self.analisis.id}"


class ParametrosSSH(models.Model):
    """
    Tabla: parametros_ssh
    Parámetros específicos de SSH
    """
    analisis = models.OneToOneField(
        Analysis,
        on_delete=models.CASCADE,
        related_name='parametros_ssh'
    )
    version = models.CharField(max_length=20, blank=True)
    protocolo = models.CharField(max_length=10, blank=True)
    algoritmos = models.TextField(blank=True, help_text="Algoritmos soportados (JSON)")
    algoritmos_mac = models.TextField(blank=True, help_text="Algoritmos MAC (JSON)")
    algoritmos_debiles = models.TextField(blank=True, help_text="Algoritmos débiles (JSON)")
    fingerprint = models.CharField(max_length=255, blank=True)
    tipo_clave = models.CharField(max_length=20, blank=True)
    longitud_clave = models.IntegerField(null=True, blank=True)
    
    class Meta:
        db_table = 'parametros_ssh'
    
    def __str__(self):
        return f"SSH Params - {self.version} - Analysis {self.analisis.id}"


class ParametrosWeb(models.Model):
    """
    Tabla: parametros_web
    Parámetros de seguridad web (headers, etc.)
    """
    analisis = models.OneToOneField(
        Analysis,
        on_delete=models.CASCADE,
        related_name='parametros_web'
    )
    hsts = models.BooleanField(null=True, help_text="HTTP Strict Transport Security")
    expect_ct = models.BooleanField(null=True, help_text="Certificate Transparency")
    hpkp = models.BooleanField(null=True, help_text="HTTP Public Key Pinning")
    fecha_hora_servidor = models.DateTimeField(null=True, blank=True)
    sni = models.BooleanField(null=True, help_text="Server Name Indication")
    ocsp_stapling = models.BooleanField(null=True, help_text="OCSP Stapling")
    
    # Headers adicionales
    content_security_policy = models.TextField(blank=True)
    x_frame_options = models.CharField(max_length=50, blank=True)
    x_content_type_options = models.CharField(max_length=50, blank=True)
    referrer_policy = models.CharField(max_length=50, blank=True)
    
    class Meta:
        db_table = 'parametros_web'
    
    def __str__(self):
        return f"Web Params - Analysis {self.analisis.id}"


class OtrosParametros(models.Model):
    """
    Tabla: otros_parametros
    Otros parámetros y métricas
    """
    analisis = models.OneToOneField(
        Analysis,
        on_delete=models.CASCADE,
        related_name='otros_parametros'
    )
    tiempo_respuesta_ssl = models.IntegerField(null=True, blank=True, help_text="Milisegundos")
    disponibilidad = models.BooleanField(default=True)
    observaciones = models.TextField(blank=True)
    
    # Métricas adicionales
    handshake_time_ms = models.IntegerField(null=True, blank=True)
    certificate_chain_size = models.IntegerField(null=True, blank=True)
    compression_supported = models.BooleanField(null=True)
    renegotiation_secure = models.BooleanField(null=True)
    
    class Meta:
        db_table = 'otros_parametros'
    
    def __str__(self):
        return f"Other Params - Analysis {self.analisis.id}"
