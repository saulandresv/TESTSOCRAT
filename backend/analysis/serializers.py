from rest_framework import serializers
from .models import (
    Analysis, ParametrosGenerales, ParametrosTLS, Vulnerabilidades,
    CadenaCertificacion, ParametrosSSH, ParametrosWeb, OtrosParametros
)


class ParametrosGeneralesSerializer(serializers.ModelSerializer):
    class Meta:
        model = ParametrosGenerales
        fields = '__all__'
        read_only_fields = ['analisis']


class ParametrosTLSSerializer(serializers.ModelSerializer):
    class Meta:
        model = ParametrosTLS
        fields = '__all__'
        read_only_fields = ['analisis']


class VulnerabilidadesSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vulnerabilidades
        fields = '__all__'
        read_only_fields = ['analisis']


class CadenaCertificacionSerializer(serializers.ModelSerializer):
    class Meta:
        model = CadenaCertificacion
        fields = '__all__'
        read_only_fields = ['analisis']


class ParametrosSSHSerializer(serializers.ModelSerializer):
    class Meta:
        model = ParametrosSSH
        fields = '__all__'
        read_only_fields = ['analisis']


class ParametrosWebSerializer(serializers.ModelSerializer):
    class Meta:
        model = ParametrosWeb
        fields = '__all__'
        read_only_fields = ['analisis']


class OtrosParametrosSerializer(serializers.ModelSerializer):
    class Meta:
        model = OtrosParametros
        fields = '__all__'
        read_only_fields = ['analisis']


class AnalysisDetailSerializer(serializers.ModelSerializer):
    """
    Serializer completo para análisis con todos los parámetros
    """
    parametros_generales = ParametrosGeneralesSerializer(read_only=True)
    parametros_tls = ParametrosTLSSerializer(read_only=True)
    parametros_ssh = ParametrosSSHSerializer(read_only=True)
    parametros_web = ParametrosWebSerializer(read_only=True)
    otros_parametros = OtrosParametrosSerializer(read_only=True)
    cadena_certificacion = CadenaCertificacionSerializer(read_only=True)
    vulnerabilidades = VulnerabilidadesSerializer(many=True, read_only=True)
    
    # Campos calculados
    certificado_info = serializers.SerializerMethodField()
    duration_seconds = serializers.SerializerMethodField()
    vulnerabilities_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Analysis
        fields = [
            'id', 'certificado', 'certificado_info', 'tipo', 'tuvo_exito',
            'fecha_inicio', 'fecha_fin', 'duration_seconds', 'comentarios',
            'triggered_by', 'error_message', 'vulnerabilities_count',
            'parametros_generales', 'parametros_tls', 'parametros_ssh',
            'parametros_web', 'otros_parametros', 'cadena_certificacion',
            'vulnerabilidades'
        ]
        read_only_fields = ['id', 'fecha_inicio']
    
    def get_certificado_info(self, obj):
        """Información básica del certificado"""
        cert = obj.certificado
        target = cert.ip or cert.url
        return {
            'id': cert.id,
            'target': target,
            'puerto': cert.puerto,
            'protocolo': cert.protocolo,
            'cliente': cert.cliente.name
        }
    
    def get_duration_seconds(self, obj):
        """Duración del análisis en segundos"""
        if obj.fecha_fin and obj.fecha_inicio:
            return (obj.fecha_fin - obj.fecha_inicio).total_seconds()
        return None
    
    def get_vulnerabilities_count(self, obj):
        """Contador de vulnerabilidades por severidad"""
        vulns = obj.vulnerabilidades.all()
        return {
            'total': vulns.count(),
            'critical': vulns.filter(severity='CRITICAL').count(),
            'high': vulns.filter(severity='HIGH').count(),
            'medium': vulns.filter(severity='MEDIUM').count(),
            'low': vulns.filter(severity='LOW').count(),
        }


class AnalysisListSerializer(serializers.ModelSerializer):
    """
    Serializer básico para lista de análisis
    """
    certificado_info = serializers.SerializerMethodField()
    vulnerabilities_summary = serializers.SerializerMethodField()
    
    class Meta:
        model = Analysis
        fields = [
            'id', 'certificado', 'certificado_info', 'tipo', 'tuvo_exito',
            'fecha_inicio', 'fecha_fin', 'triggered_by', 'vulnerabilities_summary'
        ]
    
    def get_certificado_info(self, obj):
        cert = obj.certificado
        target = cert.ip or cert.url
        return f"{target}:{cert.puerto}"
    
    def get_vulnerabilities_summary(self, obj):
        """Resumen de vulnerabilidades"""
        vulns = obj.vulnerabilidades.all()
        critical_high = vulns.filter(severity__in=['CRITICAL', 'HIGH']).count()
        return {
            'total': vulns.count(),
            'critical_high': critical_high
        }


class AnalysisCreateSerializer(serializers.ModelSerializer):
    """
    Serializer para crear análisis
    """
    class Meta:
        model = Analysis
        fields = ['certificado', 'tipo', 'comentarios', 'triggered_by']
    
    def validate_certificado(self, value):
        """Validar que el certificado esté activo"""
        if not value.active:
            raise serializers.ValidationError("No se puede analizar un certificado inactivo")
        return value