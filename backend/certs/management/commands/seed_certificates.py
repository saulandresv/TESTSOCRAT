from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from clients.models import Client
from certs.models import Certificate
from analysis.models import Analysis, Vulnerabilidades
from certs.models import VitalityStatus
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
            Certificate.objects.all().delete()
            Client.objects.all().delete()
            
        # Crear clientes de ejemplo
        self.stdout.write('👥 Creando clientes de ejemplo...')
        clientes_data = [
            {'name': 'Banco Nacional', 'status': 'activo'},
            {'name': 'E-commerce Global', 'status': 'activo'},
            {'name': 'Universidad TechPro', 'status': 'activo'},
            {'name': 'Clínica Salud Plus', 'status': 'activo'},
            {'name': 'Startup Innovation', 'status': 'activo'}
        ]
        
        clientes_creados = []
        for cliente_data in clientes_data:
            cliente, created = Client.objects.get_or_create(
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
            
            certificado = Certificate.objects.create(**certificado_data)
            certificados_creados.append(certificado)
            
            # Crear vitalidad simulada
            estado = random.choice(['activo', 'inactivo', 'activo', 'activo'])  # 75% activos
            VitalityStatus.objects.create(
                certificado=certificado,
                estado=estado,
                response_time_ms=random.randint(50, 500),
                error_message='' if estado == 'activo' else 'No se pudo conectar al servidor'
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
                
                # Crear análisis básico
                analysis = Analysis.objects.create(
                    certificado=certificado,
                    tipo='SSL_TLS',
                    tuvo_exito=True,
                    fecha_inicio=fecha_analisis,
                    fecha_fin=fecha_analisis + timedelta(minutes=random.randint(2, 10)),
                    comentarios='Análisis automático generado por seeder',
                    triggered_by='MANUAL'
                )

                # Crear vulnerabilidades si es necesario
                if random.choice([True, False, False]):  # 33% con vulnerabilidades
                    vuln_data = random.choice(vulnerabilidades_posibles)
                    Vulnerabilidades.objects.create(
                        analisis=analysis,
                        vulnerabilidad=vuln_data['name'],
                        severity=vuln_data['severity'],
                        description=vuln_data['description']
                    )
                
                self.stdout.write(f'  🔍 Análisis creado para {target_display}')
            
            self.stdout.write(f'  ✅ Certificado creado: {target_display}:{cert_data["puerto"]} ({cert_data["protocolo"]}) -> {cliente.name}')
        
        # Estadísticas finales
        self.stdout.write('\n📊 Resumen de datos creados:')
        self.stdout.write(f'  👥 Clientes: {Client.objects.count()}')
        self.stdout.write(f'  🔒 Certificados: {Certificate.objects.count()}')
        self.stdout.write(f'  💗 Controles de vitalidad: {VitalityStatus.objects.count()}')
        self.stdout.write(f'  🔍 Análisis SSL: {Analysis.objects.count()}')

        certificados_activos = VitalityStatus.objects.filter(estado='activo').count()
        certificados_con_vulnerabilidades = Vulnerabilidades.objects.count()
        
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