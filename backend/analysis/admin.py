from django.contrib import admin
from .models import (
    Analysis, ParametrosGenerales, ParametrosTLS, Vulnerabilidades,
    CadenaCertificacion, ParametrosSSH, ParametrosWeb, OtrosParametros
)


class VulnerabilidadesInline(admin.TabularInline):
    model = Vulnerabilidades
    extra = 0
    readonly_fields = ['vulnerabilidad', 'severity', 'description']


class ParametrosGeneralesInline(admin.StackedInline):
    model = ParametrosGenerales
    can_delete = False


class ParametrosTLSInline(admin.StackedInline):
    model = ParametrosTLS
    can_delete = False


class CadenaCertificacionInline(admin.StackedInline):
    model = CadenaCertificacion
    can_delete = False


@admin.register(Analysis)
class AnalysisAdmin(admin.ModelAdmin):
    list_display = ['id', 'certificado', 'tipo', 'tuvo_exito', 'fecha_inicio', 'triggered_by']
    list_filter = ['tipo', 'tuvo_exito', 'triggered_by', 'fecha_inicio']
    search_fields = ['certificado__url', 'certificado__ip', 'comentarios']
    readonly_fields = ['fecha_inicio', 'fecha_fin', 'error_message']
    
    inlines = [
        ParametrosGeneralesInline,
        ParametrosTLSInline, 
        CadenaCertificacionInline,
        VulnerabilidadesInline
    ]
    
    fieldsets = (
        ('Información Básica', {
            'fields': ('certificado', 'tipo', 'triggered_by', 'comentarios')
        }),
        ('Estado', {
            'fields': ('tuvo_exito', 'fecha_inicio', 'fecha_fin', 'error_message')
        }),
    )


@admin.register(ParametrosGenerales)
class ParametrosGeneralesAdmin(admin.ModelAdmin):
    list_display = ['analisis', 'common_name', 'issuer', 'fecha_fin', 'dias_restantes']
    list_filter = ['dias_restantes', 'fecha_fin']
    search_fields = ['common_name', 'issuer', 'subject']
    readonly_fields = ['analisis']


@admin.register(ParametrosTLS)
class ParametrosTLSAdmin(admin.ModelAdmin):
    list_display = ['analisis', 'tls12_supported', 'tls13_supported', 'pfs']
    list_filter = ['tls12_supported', 'tls13_supported', 'pfs', 'sslv2_supported', 'sslv3_supported']
    readonly_fields = ['analisis']


@admin.register(Vulnerabilidades)
class VulnerabilidadesAdmin(admin.ModelAdmin):
    list_display = ['vulnerabilidad', 'severity', 'analisis', 'description']
    list_filter = ['severity', 'vulnerabilidad']
    search_fields = ['vulnerabilidad', 'description']
    readonly_fields = ['analisis']


@admin.register(CadenaCertificacion)
class CadenaCertificacionAdmin(admin.ModelAdmin):
    list_display = ['analisis', 'cadena_ok', 'errores', 'autofirmado']
    list_filter = ['cadena_ok', 'errores', 'autofirmado']
    readonly_fields = ['analisis']


@admin.register(ParametrosSSH)
class ParametrosSSHAdmin(admin.ModelAdmin):
    list_display = ['analisis', 'version', 'protocolo', 'tipo_clave', 'longitud_clave']
    list_filter = ['version', 'protocolo', 'tipo_clave']
    readonly_fields = ['analisis']


@admin.register(ParametrosWeb) 
class ParametrosWebAdmin(admin.ModelAdmin):
    list_display = ['analisis', 'hsts', 'expect_ct', 'hpkp', 'sni']
    list_filter = ['hsts', 'expect_ct', 'hpkp', 'sni', 'ocsp_stapling']
    readonly_fields = ['analisis']


@admin.register(OtrosParametros)
class OtrosParametrosAdmin(admin.ModelAdmin):
    list_display = ['analisis', 'tiempo_respuesta_ssl', 'disponibilidad', 'handshake_time_ms']
    list_filter = ['disponibilidad', 'compression_supported', 'renegotiation_secure']
    readonly_fields = ['analisis']
