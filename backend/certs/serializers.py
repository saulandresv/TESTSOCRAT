from rest_framework import serializers
from django.core.exceptions import ValidationError
from .models import Certificate, VitalityStatus


class VitalityStatusSerializer(serializers.ModelSerializer):
    """Serializer for VitalityStatus"""
    
    class Meta:
        model = VitalityStatus
        fields = ['id', 'hora', 'estado', 'response_time_ms', 'error_message']
        read_only_fields = ['id', 'hora']


class CertificateSerializer(serializers.ModelSerializer):
    """Serializer for Certificate"""
    
    latest_vitality = serializers.SerializerMethodField()
    vitality_count = serializers.SerializerMethodField()
    cliente_nombre = serializers.CharField(source='cliente.name', read_only=True)
    
    class Meta:
        model = Certificate
        fields = [
            'id', 'cliente', 'cliente_nombre', 'nombre_certificado',
            'ip', 'url', 'puerto', 'protocolo', 'frecuencia_analisis',
            'fecha_proxima_revision', 'fecha_expiracion', 'active',
            'created_at', 'updated_at', 'latest_vitality', 'vitality_count'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'cliente_nombre']
    
    def get_latest_vitality(self, obj):
        """Get the latest vitality status"""
        latest = obj.vitality_checks.first()  # already ordered by -hora
        if latest:
            return VitalityStatusSerializer(latest).data
        return None
    
    def get_vitality_count(self, obj):
        """Get count of vitality checks"""
        return obj.vitality_checks.count()
    
    def validate(self, attrs):
        """Validate certificate data"""
        # Crear instancia temporal para validar
        instance = Certificate(**attrs)
        if hasattr(self, 'instance') and self.instance:
            instance.pk = self.instance.pk

        try:
            instance.clean()
        except ValidationError as e:
            raise serializers.ValidationError(str(e))

        return attrs


class CertificateCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating certificates with minimal fields"""
    
    class Meta:
        model = Certificate
        fields = [
            'cliente', 'nombre_certificado', 'ip', 'url', 
            'puerto', 'protocolo', 'frecuencia_analisis'
        ]
    
    def validate(self, attrs):
        """Validate certificate data"""
        # Crear instancia temporal para validar
        instance = Certificate(**attrs)
        if hasattr(self, 'instance') and self.instance:
            instance.pk = self.instance.pk

        try:
            instance.clean()
        except ValidationError as e:
            raise serializers.ValidationError(str(e))

        return attrs