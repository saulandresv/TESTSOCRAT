from django.db import models
from django.utils import timezone
import uuid


class Report(models.Model):
    """
    Modelo para reportes generados
    """
    REPORT_TYPES = [
        ('CERTIFICATE_SUMMARY', 'Resumen de Certificados'),
        ('CERTIFICATE_DETAILED', 'Reporte Detallado de Certificados'),
        ('VULNERABILITY_SUMMARY', 'Resumen de Vulnerabilidades'),
        ('CLIENT_OVERVIEW', 'Vista General de Cliente'),
    ]
    
    FORMATS = [
        ('PDF', 'PDF'),
        ('EXCEL', 'Excel'),
        ('JSON', 'JSON'),
    ]
    
    STATUS_CHOICES = [
        ('PENDING', 'Pendiente'),
        ('PROCESSING', 'Procesando'),
        ('COMPLETED', 'Completado'),
        ('FAILED', 'Fallido'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    client = models.ForeignKey(
        'clients.Client',
        on_delete=models.CASCADE,
        related_name='reports',
        help_text='Cliente para el cual se genera el reporte'
    )
    requested_by = models.ForeignKey(
        'accounts.User',
        on_delete=models.CASCADE,
        related_name='requested_reports'
    )
    
    # Configuración del reporte
    report_type = models.CharField(max_length=50, choices=REPORT_TYPES)
    format = models.CharField(max_length=10, choices=FORMATS)
    
    # Filtros aplicados (JSON)
    filters = models.JSONField(
        default=dict,
        help_text='Filtros aplicados: fechas, tipos de certificados, etc.'
    )
    
    # Estado y archivos
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    file_path = models.CharField(max_length=500, blank=True)
    file_size = models.PositiveIntegerField(null=True, blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(default=timezone.now)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    # Resultados
    total_certificates = models.PositiveIntegerField(null=True, blank=True)
    total_analyses = models.PositiveIntegerField(null=True, blank=True)
    total_vulnerabilities = models.PositiveIntegerField(null=True, blank=True)
    
    # Error handling
    error_message = models.TextField(blank=True)
    
    class Meta:
        db_table = 'reports'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['client', 'status']),
            models.Index(fields=['requested_by', 'created_at']),
        ]
    
    def __str__(self):
        return f'{self.get_report_type_display()} - {self.client.name} ({self.status})'
    
    @property
    def is_ready(self):
        return self.status == 'COMPLETED' and self.file_path
    
    @property
    def duration(self):
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None


class ReportSchedule(models.Model):
    """
    Programación de reportes automáticos
    """
    FREQUENCIES = [
        ('DAILY', 'Diario'),
        ('WEEKLY', 'Semanal'),
        ('MONTHLY', 'Mensual'),
        ('QUARTERLY', 'Trimestral'),
    ]
    
    client = models.ForeignKey('clients.Client', on_delete=models.CASCADE)
    report_type = models.CharField(max_length=50, choices=Report.REPORT_TYPES)
    format = models.CharField(max_length=10, choices=Report.FORMATS)
    frequency = models.CharField(max_length=20, choices=FREQUENCIES)
    
    # Configuración
    filters = models.JSONField(default=dict)
    email_recipients = models.JSONField(
        default=list,
        help_text='Lista de emails para envío automático'
    )
    
    # Control
    active = models.BooleanField(default=True)
    next_run = models.DateTimeField()
    last_run = models.DateTimeField(null=True, blank=True)
    
    created_at = models.DateTimeField(default=timezone.now)
    created_by = models.ForeignKey('accounts.User', on_delete=models.CASCADE)
    
    class Meta:
        db_table = 'report_schedules'
    
    def __str__(self):
        return f'{self.get_report_type_display()} - {self.client.name} ({self.frequency})'
