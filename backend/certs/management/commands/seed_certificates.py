from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from clients.models import Cliente
from certs.models import Certificado
from analysis.models import AnalisisSSL, VitalidadCertificado
from datetime import datetime, timedelta
import random

User = get_user_model()

class Command(BaseCommand):
    help = 'Poblar base de datos con certificados SSL de ejemplo para testing'

    def add_arguments(self, parser):
        parser.add_argument(
            '--clean',
            action='store_true',
            help='Limpiar datos existentes antes de crear los ejemplos',
        )
        
        parser.add_argument(
            '--count',
            type=int,
            default=20,
            help='Número de certificados de ejemplo a crear (default: 20)',
        )

    def handle(self, *args, **options):
        if options['clean']:
            self.stdout.write('🗑️  Limpiando datos existentes...')
            Certificado.objects.all().delete()
            Cliente.objects.all().delete()
            
        # Crear clientes de ejemplo
        self.stdout.write('👥 Creando clientes de ejemplo...')
        clientes_data = [
            {
                'name': 'Banco Nacional',
                'description': 'Entidad financiera principal',
                'contact_email': 'seguridad@banconacional.com',
                'contact_phone': '+56-2-2555-0001'
            },
            {
                'name': 'E-commerce Global',
                'description': 'Plataforma de comercio electrónico',
                'contact_email': 'admin@ecommerce.com',
                'contact_phone': '+56-9-8888-0002'
            },
            {
                'name': 'Universidad TechPro',
                'description': 'Institución educacional superior',
                'contact_email': 'it@utechpro.edu',
                'contact_phone': '+56-2-2777-0003'
            },
            {
                'name': 'Clínica Salud Plus',
                'description': 'Centro médico privado',
                'contact_email': 'sistemas@saludplus.cl',
                'contact_phone': '+56-2-2333-0004'
            },
            {
                'name': 'Startup Innovation',
                'description': 'Empresa tecnológica emergente',
                'contact_email': 'devops@startup-innovation.com',
                'contact_phone': '+56-9-7777-0005'
            }
        ]
        
        clientes_creados = []
        for cliente_data in clientes_data:
            cliente, created = Cliente.objects.get_or_create(
                name=cliente_data['name'],
                defaults=cliente_data
            )
            clientes_creados.append(cliente)
            if created:
                self.stdout.write(f'  ✅ Cliente creado: {cliente.name}')
            else:
                self.stdout.write(f'  ↪️  Cliente existente: {cliente.name}')
        
        # Certificados de ejemplo con sitios reales y casos de prueba
        certificados_ejemplo = [
            # Sitios populares (reales)
            {'url': 'google.com', 'puerto': 443, 'protocolo': 'HTTPS'},
            {'url': 'github.com', 'puerto': 443, 'protocolo': 'HTTPS'},
            {'url': 'stackoverflow.com', 'puerto': 443, 'protocolo': 'HTTPS'},
            {'url': 'microsoft.com', 'puerto': 443, 'protocolo': 'HTTPS'},
            {'url': 'amazon.com', 'puerto': 443, 'protocolo': 'HTTPS'},
            {'url': 'cloudflare.com', 'puerto': 443, 'protocolo': 'HTTPS'},
            {'url': 'apple.com', 'puerto': 443, 'protocolo': 'HTTPS'},
            {'url': 'facebook.com', 'puerto': 443, 'protocolo': 'HTTPS'},
            {'url': 'linkedin.com', 'puerto': 443, 'protocolo': 'HTTPS'},
            {'url': 'twitter.com', 'puerto': 443, 'protocolo': 'HTTPS'},
            
            # Sitios con diferentes puertos y protocolos
            {'url': 'mail.google.com', 'puerto': 993, 'protocolo': 'IMAP'},
            {'url': 'smtp.gmail.com', 'puerto': 587, 'protocolo': 'SMTP'},
            {'url': 'outlook.live.com', 'puerto': 993, 'protocolo': 'IMAP'},
            {'url': 'imap.mail.yahoo.com', 'puerto': 993, 'protocolo': 'IMAP'},
            
            # IPs públicas para testing
            {'ip': '8.8.8.8', 'puerto': 443, 'protocolo': 'HTTPS'},
            {'ip': '1.1.1.1', 'puerto': 443, 'protocolo': 'HTTPS'},
            {'ip': '208.67.222.222', 'puerto': 443, 'protocolo': 'HTTPS'},
            
            # Casos especiales
            {'url': 'httpbin.org', 'puerto': 443, 'protocolo': 'HTTPS'},
            {'url': 'example.com', 'puerto': 443, 'protocolo': 'HTTPS'},
            {'url': 'badssl.com', 'puerto': 443, 'protocolo': 'HTTPS'},  # Para testing de vulnerabilidades
        ]
        
        # Crear certificados
        self.stdout.write(f'🔒 Creando {min(options["count"], len(certificados_ejemplo))} certificados de ejemplo...')
        
        certificados_creados = []
        for i, cert_data in enumerate(certificados_ejemplo[:options['count']]):
            cliente = random.choice(clientes_creados)
            
            # Determinar nombre del certificado basado en URL/IP
            if 'url' in cert_data:
                nombre_cert = f"Certificado {cert_data['url'].replace('.', '_').upper()}"
                target_display = cert_data['url']
            else:
                nombre_cert = f"Certificado IP_{cert_data['ip'].replace('.', '_')}"
                target_display = cert_data['ip']
            
            certificado_data = {
                'cliente': cliente,
                'nombre_certificado': nombre_cert,
                'puerto': cert_data['puerto'],
                'protocolo': cert_data['protocolo'],
                'frecuencia_analisis': random.choice([7, 15, 30]),
                **cert_data  # url o ip
            }
            
            certificado = Certificado.objects.create(**certificado_data)
            certificados_creados.append(certificado)
            
            # Crear vitalidad simulada
            estado = random.choice(['activo', 'inactivo', 'activo', 'activo'])  # 75% activos
            VitalidadCertificado.objects.create(
                certificado=certificado,
                estado=estado,
                tiempo_respuesta=random.randint(50, 500),
                mensaje_estado='Certificado verificado automáticamente' if estado == 'activo' else 'No se pudo conectar al servidor',
                fecha_verificacion=datetime.now() - timedelta(hours=random.randint(1, 24))
            )
            
            # Crear análisis SSL simulado para algunos certificados
            if random.choice([True, False, True]):  # 66% tienen análisis
                fecha_analisis = datetime.now() - timedelta(days=random.randint(1, 15))
                
                # Simular resultados de análisis
                vulnerabilidades_posibles = [
                    {'name': 'WEAK_CIPHERS', 'severity': 'MEDIUM', 'description': 'Cifrados débiles detectados'},
                    {'name': 'POODLE', 'severity': 'HIGH', 'description': 'SSLv3 habilitado - vulnerable a POODLE'},
                    {'name': 'SHORT_KEY_LENGTH', 'severity': 'HIGH', 'description': 'Longitudes de clave cortas detectadas'},
                ]
                
                # Algunos certificados sin vulnerabilidades
                if random.choice([True, False, False]):  # 33% con vulnerabilidades
                    vulnerabilidades = [random.choice(vulnerabilidades_posibles)]
                    estado_general = 'VULNERABILITIES_FOUND'
                    puntuacion = random.randint(60, 79)
                else:
                    vulnerabilidades = []
                    estado_general = 'SECURE'
                    puntuacion = random.randint(80, 100)
                
                resultados_simulados = {
                    'timestamp': fecha_analisis.isoformat(),
                    'target': f"{target_display}:{cert_data['puerto']}",
                    'summary': {
                        'protocols': {
                            'TLS1.2': True,
                            'TLS1.3': random.choice([True, False]),
                            'SSLv3': random.choice([True, False, False, False])  # Mayormente False
                        },
                        'vulnerabilities': vulnerabilidades,
                        'certificate': {
                            'issuer': random.choice([
                                'Let\'s Encrypt Authority X3',
                                'DigiCert SHA2 Extended Validation Server CA',
                                'Cloudflare Inc ECC CA-3',
                                'Amazon',
                                'Google Trust Services'
                            ]),
                            'not_valid_after': (fecha_analisis + timedelta(days=random.randint(30, 365))).isoformat(),
                            'signature_algorithm': 'sha256WithRSAEncryption'
                        },
                        'recommendations': [
                            'Enable TLS 1.3 for better security',
                            'Disable SSLv3 to prevent POODLE attacks'
                        ] if vulnerabilidades else ['Configuration looks secure']
                    }
                }
                
                AnalisisSSL.objects.create(
                    certificado=certificado,
                    tipo_analisis='SSL_TLS',
                    estado_analisis='COMPLETED',
                    fecha_inicio=fecha_analisis,
                    fecha_fin=fecha_analisis + timedelta(minutes=random.randint(2, 10)),
                    resultados=resultados_simulados,
                    puntuacion_seguridad=puntuacion,
                    vulnerabilidades_encontradas=len(vulnerabilidades),
                    estado_general=estado_general
                )
                
                self.stdout.write(f'  🔍 Análisis creado para {target_display} - Estado: {estado_general}')
            
            self.stdout.write(f'  ✅ Certificado creado: {target_display}:{cert_data["puerto"]} ({cert_data["protocolo"]}) -> {cliente.name}')
        
        # Estadísticas finales
        self.stdout.write('\n📊 Resumen de datos creados:')
        self.stdout.write(f'  👥 Clientes: {Cliente.objects.count()}')
        self.stdout.write(f'  🔒 Certificados: {Certificado.objects.count()}')
        self.stdout.write(f'  💗 Controles de vitalidad: {VitalidadCertificado.objects.count()}')
        self.stdout.write(f'  🔍 Análisis SSL: {AnalisisSSL.objects.count()}')
        
        certificados_activos = VitalidadCertificado.objects.filter(estado='activo').count()
        certificados_con_vulnerabilidades = AnalisisSSL.objects.filter(vulnerabilidades_encontradas__gt=0).count()
        
        self.stdout.write(f'  🟢 Certificados activos: {certificados_activos}')
        self.stdout.write(f'  ⚠️  Certificados con vulnerabilidades: {certificados_con_vulnerabilidades}')
        
        self.stdout.write('\n✅ Seeder ejecutado exitosamente!')
        self.stdout.write('\n🚀 Ahora puedes:')
        self.stdout.write('  1. Ver los certificados en el frontend')
        self.stdout.write('  2. Ejecutar análisis manuales')
        self.stdout.write('  3. Probar las funciones de filtrado')
        self.stdout.write('  4. Revisar los reportes de análisis')
        self.stdout.write('\n💡 Usa: python manage.py seed_certificates --clean --count 10')
        self.stdout.write('   para regenerar con 10 certificados de ejemplo')