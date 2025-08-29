from django.contrib import admin
from .models import Certificate, VitalityStatus


@admin.register(Certificate)
class CertificateAdmin(admin.ModelAdmin):
    list_display = ['__str__', 'cliente', 'protocolo', 'fecha_expiracion', 'active', 'created_at']
    list_filter = ['protocolo', 'active', 'cliente', 'created_at']
    search_fields = ['nombre_certificado', 'ip', 'url']
    readonly_fields = ['created_at', 'updated_at']
    
    fieldsets = (
        ('Información Básica', {
            'fields': ('cliente', 'nombre_certificado', 'protocolo', 'active')
        }),
        ('Conexión', {
            'fields': ('ip', 'url', 'puerto')
        }),
        ('Configuración', {
            'fields': ('frecuencia_analisis', 'fecha_proxima_revision', 'fecha_expiracion')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(VitalityStatus)
class VitalityStatusAdmin(admin.ModelAdmin):
    list_display = ['certificado', 'estado', 'hora', 'response_time_ms']
    list_filter = ['estado', 'hora']
    search_fields = ['certificado__nombre_certificado', 'certificado__ip', 'certificado__url']
    readonly_fields = ['hora']
    
    def has_add_permission(self, request):
        return False  # Solo lectura desde admin, se crean via API
