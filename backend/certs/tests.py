from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework.authtoken.models import Token
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
from clients.models import Cliente
from certs.models import Certificado, VitalidadCertificado
from analysis.models import AnalisisSSL, Vulnerabilidad
from certs.serializers import CertificadoSerializer

User = get_user_model()


class CertificadoModelTest(TestCase):
    """Test del modelo Certificado"""
    
    def setUp(self):
        self.cliente = Cliente.objects.create(
            name="Cliente Test",
            description="Cliente para pruebas",
            contact_email="test@cliente.com"
        )
    
    def test_crear_certificado_url(self):
        """Test crear certificado con URL"""
        certificado = Certificado.objects.create(
            cliente=self.cliente,
            url="google.com",
            puerto=443,
            protocolo="HTTPS",
            frecuencia_analisis=30
        )
        self.assertEqual(certificado.url, "google.com")
        self.assertEqual(certificado.puerto, 443)
        self.assertEqual(certificado.cliente, self.cliente)
        self.assertIsNone(certificado.ip)
    
    def test_crear_certificado_ip(self):
        """Test crear certificado con IP"""
        certificado = Certificado.objects.create(
            cliente=self.cliente,
            ip="8.8.8.8",
            puerto=443,
            protocolo="HTTPS",
            frecuencia_analisis=30
        )
        self.assertEqual(certificado.ip, "8.8.8.8")
        self.assertEqual(certificado.puerto, 443)
        self.assertIsNone(certificado.url)
    
    def test_str_representation(self):
        """Test representación string del certificado"""
        certificado = Certificado.objects.create(
            cliente=self.cliente,
            url="example.com",
            puerto=443,
            protocolo="HTTPS",
            frecuencia_analisis=30
        )
        expected = f"example.com:443 ({self.cliente.name})"
        self.assertEqual(str(certificado), expected)
    
    def test_get_target_display(self):
        """Test método get_target_display"""
        # Certificado con URL
        cert_url = Certificado.objects.create(
            cliente=self.cliente,
            url="example.com",
            puerto=443,
            protocolo="HTTPS",
            frecuencia_analisis=30
        )
        self.assertEqual(cert_url.get_target_display(), "example.com")
        
        # Certificado con IP
        cert_ip = Certificado.objects.create(
            cliente=self.cliente,
            ip="192.168.1.1",
            puerto=22,
            protocolo="SSH",
            frecuencia_analisis=30
        )
        self.assertEqual(cert_ip.get_target_display(), "192.168.1.1")


class VitalidadCertificadoModelTest(TestCase):
    """Test del modelo VitalidadCertificado"""
    
    def setUp(self):
        self.cliente = Cliente.objects.create(
            name="Cliente Test",
            description="Cliente para pruebas",
            contact_email="test@cliente.com"
        )
        self.certificado = Certificado.objects.create(
            cliente=self.cliente,
            url="test.com",
            puerto=443,
            protocolo="HTTPS",
            frecuencia_analisis=30
        )
    
    def test_crear_vitalidad(self):
        """Test crear registro de vitalidad"""
        vitalidad = VitalidadCertificado.objects.create(
            certificado=self.certificado,
            estado="activo",
            tiempo_respuesta=150,
            mensaje_estado="Certificado válido"
        )
        self.assertEqual(vitalidad.estado, "activo")
        self.assertEqual(vitalidad.tiempo_respuesta, 150)
        self.assertEqual(vitalidad.certificado, self.certificado)
    
    def test_fecha_verificacion_auto_set(self):
        """Test que fecha_verificacion se establece automáticamente"""
        vitalidad = VitalidadCertificado.objects.create(
            certificado=self.certificado,
            estado="activo",
            tiempo_respuesta=100
        )
        self.assertIsNotNone(vitalidad.fecha_verificacion)


class CertificadoAPITest(APITestCase):
    """Test de la API de Certificados"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            email="test@example.com",
            password="testpass123"
        )
        self.token = Token.objects.create(user=self.user)
        self.cliente = Cliente.objects.create(
            name="Cliente API Test",
            description="Cliente para pruebas de API",
            contact_email="api@cliente.com"
        )
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token.key)
    
    def test_get_certificados_list(self):
        """Test obtener lista de certificados"""
        # Crear certificados de prueba
        Certificado.objects.create(
            cliente=self.cliente,
            url="test1.com",
            puerto=443,
            protocolo="HTTPS",
            frecuencia_analisis=30
        )
        Certificado.objects.create(
            cliente=self.cliente,
            ip="192.168.1.100",
            puerto=22,
            protocolo="SSH",
            frecuencia_analisis=15
        )
        
        url = reverse('certificado-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 2)
    
    def test_create_certificado_url(self):
        """Test crear certificado con URL via API"""
        url = reverse('certificado-list')
        data = {
            'cliente': self.cliente.id,
            'url': 'newsite.com',
            'puerto': 443,
            'protocolo': 'HTTPS',
            'frecuencia_analisis': 30
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Certificado.objects.count(), 1)
        certificado = Certificado.objects.first()
        self.assertEqual(certificado.url, 'newsite.com')
        self.assertEqual(certificado.puerto, 443)
    
    def test_unauthorized_access(self):
        """Test acceso no autorizado a la API"""
        self.client.credentials()  # Remover token
        url = reverse('certificado-list')
        
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class MockedSSLAnalysisTest(TestCase):
    """Tests con mocks para análisis SSL"""
    
    def setUp(self):
        self.cliente = Cliente.objects.create(
            name="Cliente Mock Test",
            description="Cliente para pruebas con mocks",
            contact_email="mock@cliente.com"
        )
        self.certificado = Certificado.objects.create(
            cliente=self.cliente,
            url="mock-test.com",
            puerto=443,
            protocolo="HTTPS",
            frecuencia_analisis=30
        )
    
    @patch('analysis.external_tools.ExternalSSLAnalyzer.analyze_with_nmap')
    def test_nmap_analysis_success(self, mock_nmap):
        """Test análisis con nmap (mocked)"""
        # Configurar mock response
        mock_nmap.return_value = {
            'ssl_ciphers': ['TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256'],
            'tls_versions': ['TLSv1.2', 'TLSv1.3'],
            'certificate_info': {
                'issuer': 'Let\'s Encrypt Authority X3',
                'expires': '2024-12-01'
            }
        }
        
        from analysis.external_tools import ExternalSSLAnalyzer
        analyzer = ExternalSSLAnalyzer()
        
        result = analyzer.analyze_with_nmap('mock-test.com', 443)
        
        mock_nmap.assert_called_once_with('mock-test.com', 443)
        self.assertIn('ssl_ciphers', result)
        self.assertIn('TLSv1.3', result['tls_versions'])
