"""
Serializers para reportes - Proyecto Sócrates
"""

from rest_framework import serializers
from .models import Report
from clients.models import Client


class ReportSerializer(serializers.ModelSerializer):
    """
    Serializer para lectura de reportes
    """
    client_name = serializers.CharField(source='client.name', read_only=True)
    duration = serializers.SerializerMethodField()
    file_size_mb = serializers.SerializerMethodField()
    download_url = serializers.SerializerMethodField()
    
    class Meta:
        model = Report
        fields = [
            'id', 'client', 'client_name', 'report_type', 'format',
            'status', 'created_at', 'started_at', 'completed_at',
            'duration', 'file_size_mb', 'total_certificates',
            'total_analyses', 'total_vulnerabilities', 'filters',
            'description', 'error_message', 'download_url'
        ]
        read_only_fields = [
            'id', 'status', 'created_at', 'started_at', 'completed_at',
            'duration', 'file_size_mb', 'total_certificates',
            'total_analyses', 'total_vulnerabilities', 'error_message'
        ]
    
    def get_duration(self, obj):
        """Calcular duración de generación"""
        return obj.duration
    
    def get_file_size_mb(self, obj):
        """Obtener tamaño del archivo en MB"""
        return obj.file_size_mb
    
    def get_download_url(self, obj):
        """URL de descarga si el reporte está completado"""
        if obj.status == 'COMPLETED':
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(f'/api/reports/{obj.id}/download/')
        return None


class ReportCreateSerializer(serializers.ModelSerializer):
    """
    Serializer para creación de reportes
    """
    client_id = serializers.IntegerField(write_only=True)
    
    class Meta:
        model = Report
        fields = [
            'client_id', 'report_type', 'format', 'filters', 'description'
        ]
    
    def validate_client_id(self, value):
        """Validar que el cliente existe"""
        if not Client.objects.filter(id=value).exists():
            raise serializers.ValidationError("Cliente no encontrado")
        return value
    
    def validate_report_type(self, value):
        """Validar tipo de reporte"""
        valid_types = [choice[0] for choice in Report.REPORT_TYPE_CHOICES]
        if value not in valid_types:
            raise serializers.ValidationError(f"Tipo de reporte inválido. Opciones: {valid_types}")
        return value
    
    def validate_format(self, value):
        """Validar formato"""
        valid_formats = [choice[0] for choice in Report.FORMAT_CHOICES]
        if value not in valid_formats:
            raise serializers.ValidationError(f"Formato inválido. Opciones: {valid_formats}")
        return value
    
    def validate_filters(self, value):
        """Validar estructura de filtros"""
        if value is None:
            return {}
        
        if not isinstance(value, dict):
            raise serializers.ValidationError("Los filtros deben ser un objeto JSON")
        
        # Validar filtros específicos según especificaciones
        allowed_filters = [
            'date_from', 'date_to', 'protocolo', 'expires_before', 
            'include_expired', 'severity_min', 'client_specific'
        ]
        
        for key in value.keys():
            if key not in allowed_filters:
                raise serializers.ValidationError(f"Filtro '{key}' no válido. Filtros permitidos: {allowed_filters}")
        
        # Validar formato de fechas
        if 'date_from' in value:
            try:
                from datetime import datetime
                datetime.strptime(value['date_from'], '%Y-%m-%d')
            except ValueError:
                raise serializers.ValidationError("date_from debe tener formato YYYY-MM-DD")
        
        if 'date_to' in value:
            try:
                from datetime import datetime
                datetime.strptime(value['date_to'], '%Y-%m-%d')
            except ValueError:
                raise serializers.ValidationError("date_to debe tener formato YYYY-MM-DD")
        
        return value
    
    def create(self, validated_data):
        """Crear reporte con cliente asociado"""
        client_id = validated_data.pop('client_id')
        client = Client.objects.get(id=client_id)
        
        return Report.objects.create(
            client=client,
            **validated_data
        )


class ReportSummarySerializer(serializers.ModelSerializer):
    """
    Serializer simplificado para listados y resúmenes
    """
    client_name = serializers.CharField(source='client.name', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    
    class Meta:
        model = Report
        fields = [
            'id', 'client_name', 'report_type', 'format', 
            'status', 'status_display', 'created_at', 
            'completed_at', 'file_size_mb'
        ]