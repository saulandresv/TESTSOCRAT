from django.test import TestCase
from django.contrib.auth import get_user_model
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
from clients.models import Cliente
from certs.models import Certificado
from analysis.models import AnalisisSSL, Vulnerabilidad
from analysis.external_tools import ExternalSSLAnalyzer
from analysis.analysis_engine import SSLAnalysisEngine
import json

User = get_user_model()


class AnalisisSSLModelTest(TestCase):
    """Test del modelo AnalisisSSL"""
    
    def setUp(self):
        self.cliente = Cliente.objects.create(
            name="Cliente Analysis Test",
            description="Cliente para pruebas de análisis",
            contact_email="analysis@cliente.com"
        )
        self.certificado = Certificado.objects.create(
            cliente=self.cliente,
            url="analysis-test.com",
            puerto=443,
            protocolo="HTTPS",
            frecuencia_analisis=30
        )
    
    def test_crear_analisis_ssl(self):
        """Test crear análisis SSL"""
        analisis = AnalisisSSL.objects.create(
            certificado=self.certificado,
            tipo_analisis="SSL_TLS",
            estado_analisis="COMPLETED",
            fecha_inicio=datetime.now(),
            fecha_fin=datetime.now() + timedelta(minutes=5),
            resultados={"test": "data"},
            puntuacion_seguridad=85,
            vulnerabilidades_encontradas=2
        )
        
        self.assertEqual(analisis.tipo_analisis, "SSL_TLS")
        self.assertEqual(analisis.estado_analisis, "COMPLETED")
        self.assertEqual(analisis.puntuacion_seguridad, 85)
        self.assertEqual(analisis.certificado, self.certificado)
    
    def test_analisis_duracion_calculation(self):
        """Test cálculo de duración del análisis"""
        inicio = datetime.now()
        fin = inicio + timedelta(minutes=3, seconds=30)
        
        analisis = AnalisisSSL.objects.create(
            certificado=self.certificado,
            tipo_analisis="SSL_TLS",
            estado_analisis="COMPLETED",
            fecha_inicio=inicio,
            fecha_fin=fin,
            resultados={"test": "data"}
        )
        
        # La duración debe ser aproximadamente 210 segundos (3.5 minutos)
        duracion = (analisis.fecha_fin - analisis.fecha_inicio).total_seconds()
        self.assertAlmostEqual(duracion, 210, delta=1)


class ExternalSSLAnalyzerTest(TestCase):
    """Test de la clase ExternalSSLAnalyzer"""
    
    def setUp(self):
        self.analyzer = ExternalSSLAnalyzer()
        self.test_hostname = "test.example.com"
        self.test_port = 443
    
    @patch('subprocess.run')
    def test_analyze_with_nmap_success(self, mock_subprocess):
        """Test análisis con nmap exitoso"""
        # Mock de respuesta exitosa de nmap
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "TLSv1.2 enabled"
        mock_subprocess.return_value = mock_result
        
        result = self.analyzer.analyze_with_nmap(self.test_hostname, self.test_port)
        
        # Verificar que se llamó correctamente
        mock_subprocess.assert_called_once()
        self.assertIsInstance(result, dict)
    
    def test_check_vulnerabilities_mock(self):
        """Test verificación de vulnerabilidades"""
        # Este test usa métodos internos mockeados
        with patch.object(self.analyzer, '_test_heartbleed', return_value=True), \
             patch.object(self.analyzer, '_test_sslv3', return_value=False), \
             patch.object(self.analyzer, '_test_weak_ciphers', return_value=['RC4-MD5']):
            
            vulnerabilities = self.analyzer.check_vulnerabilities(self.test_hostname, self.test_port)
            
            self.assertIsInstance(vulnerabilities, list)
            # Debe encontrar Heartbleed y cipher débil
            vuln_names = [v['name'] for v in vulnerabilities]
            self.assertIn('HEARTBLEED', vuln_names)
            self.assertIn('WEAK_CIPHER', vuln_names)


class SSLAnalysisEngineTest(TestCase):
    """Test del motor de análisis SSL"""
    
    def setUp(self):
        self.cliente = Cliente.objects.create(
            name="Cliente Engine Test",
            description="Cliente para pruebas de motor",
            contact_email="engine@cliente.com"
        )
        self.certificado = Certificado.objects.create(
            cliente=self.cliente,
            url="engine-test.com",
            puerto=443,
            protocolo="HTTPS",
            frecuencia_analisis=30
        )
        self.engine = SSLAnalysisEngine()
    
    def test_calcular_puntuacion_sin_vulnerabilidades(self):
        """Test cálculo de puntuación sin vulnerabilidades"""
        vulnerabilidades = []
        puntuacion = self.engine.calcular_puntuacion_seguridad(vulnerabilidades)
        
        # Sin vulnerabilidades debe dar puntuación perfecta
        self.assertEqual(puntuacion, 100)
    
    def test_calcular_puntuacion_con_vulnerabilidades(self):
        """Test cálculo de puntuación con vulnerabilidades"""
        vulnerabilidades = [
            {'severity': 'CRITICAL'},
            {'severity': 'HIGH'},
            {'severity': 'MEDIUM'},
            {'severity': 'LOW'}
        ]
        
        puntuacion = self.engine.calcular_puntuacion_seguridad(vulnerabilidades)
        
        # Con vulnerabilidades críticas y altas debe bajar considerablemente
        self.assertLess(puntuacion, 60)
        self.assertGreaterEqual(puntuacion, 0)
