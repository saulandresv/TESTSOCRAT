import ssl
import socket
import subprocess
import json
import re
from datetime import datetime, date
from urllib.parse import urlparse
from django.utils import timezone

from .models import (
    Analysis, Vulnerabilidades, ParametrosGenerales, ParametrosTLS,
    CadenaCertificacion, ParametrosWeb, OtrosParametros
)
from .external_tools import ExternalSSLAnalyzer


class SSLAnalysisEngine:
    """
    Motor de análisis SSL/TLS para certificados con notificaciones integradas
    """
    
    def __init__(self):
        self.timeout = 10
        self.external_analyzer = ExternalSSLAnalyzer()
    
    def ejecutar_analisis_ssl(self, certificado):
        """
        Ejecutar análisis SSL completo con notificaciones automáticas
        """
        import logging
        logger = logging.getLogger(__name__)
        
        # Crear registro de análisis
        analisis = Analysis.objects.create(
            certificado=certificado,
            tipo='SSL_TLS',
            tuvo_exito=False,
            fecha_inicio=timezone.now()
        )
        
        try:
            # Determinar target
            target = certificado.ip or certificado.url
            if certificado.url and not certificado.url.startswith('http'):
                target = certificado.url
            
            # Ejecutar análisis con herramientas externas
            results = self.external_analyzer.comprehensive_ssl_analysis(target, certificado.puerto)
            
            # Procesar resultados
            vulnerabilities = results.get('summary', {}).get('vulnerabilities', [])
            
            # Calcular puntuación de seguridad
            security_score = self.calcular_puntuacion_seguridad(vulnerabilities)
            
            # Determinar estado general
            estado_general = self.determinar_estado_general(vulnerabilities)
            
            # Actualizar análisis
            analisis.fecha_fin = timezone.now()
            analisis.tuvo_exito = True
            analisis.comentarios = f"Análisis completado. Puntuación: {security_score}/100. Vulnerabilidades: {len(vulnerabilities)}. Estado: {estado_general}"
            analisis.save()
            
            # Crear registros de vulnerabilidades
            for vuln_data in vulnerabilities:
                Vulnerabilidades.objects.create(
                    analisis=analisis,
                    vulnerabilidad=vuln_data.get('name', 'Unknown'),
                    severity=vuln_data.get('severity', 'MEDIUM'),
                    description=vuln_data.get('description', ''),
                    recommendation=vuln_data.get('recommendation', '')
                )
            
            # Enviar notificaciones asíncronas si hay vulnerabilidades críticas
            if vulnerabilities:
                critical_vulns = [v for v in vulnerabilities if v.get('severity') in ['CRITICAL', 'HIGH']]
                if critical_vulns:
                    self._schedule_vulnerability_notification(analisis, critical_vulns)
            
            logger.info(f"SSL analysis completed for {certificado.get_target_display()}: {security_score}/100")
            return analisis
            
        except Exception as e:
            # Marcar como fallido
            analisis.fecha_fin = timezone.now()
            analisis.tuvo_exito = False
            analisis.error_message = str(e)
            analisis.save()
            
            # Enviar alerta del sistema
            self._schedule_system_alert(
                'SSL Analysis Failed',
                f'Analysis failed for {certificado.get_target_display()}: {str(e)}',
                {'certificate_id': certificado.id, 'error': str(e)}
            )
            
            logger.error(f"SSL analysis failed for {certificado.get_target_display()}: {e}")
            return analisis
    
    def calcular_puntuacion_seguridad(self, vulnerabilities):
        """
        Calcular puntuación de seguridad basada en vulnerabilidades
        """
        if not vulnerabilities:
            return 100
        
        # Sistema de puntuación
        penalties = {
            'CRITICAL': 25,
            'HIGH': 15,
            'MEDIUM': 8,
            'LOW': 3
        }
        
        total_penalty = 0
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'LOW')
            total_penalty += penalties.get(severity, 3)
        
        # Puntuación mínima de 0
        score = max(0, 100 - total_penalty)
        return score
    
    def determinar_estado_general(self, vulnerabilities):
        """
        Determinar estado general basado en vulnerabilidades
        """
        if not vulnerabilities:
            return 'SECURE'
        
        # Contar por severidad
        critical_count = sum(1 for v in vulnerabilities if v.get('severity') == 'CRITICAL')
        high_count = sum(1 for v in vulnerabilities if v.get('severity') == 'HIGH')
        
        if critical_count > 0:
            return 'CRITICAL_VULNERABILITIES'
        elif high_count > 0:
            return 'HIGH_VULNERABILITIES'
        else:
            return 'VULNERABILITIES_FOUND'
    
    def _schedule_vulnerability_notification(self, analisis, critical_vulns):
        """
        Programar notificación de vulnerabilidades críticas
        """
        try:
            from notifications.tasks import check_vulnerability_alerts
            check_vulnerability_alerts.delay()
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Error scheduling vulnerability notification: {e}")
    
    def _schedule_system_alert(self, alert_type, message, details):
        """
        Programar alerta del sistema
        """
        try:
            from notifications.tasks import send_system_alert_task
            send_system_alert_task.delay(alert_type, message, details)
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Error scheduling system alert: {e}")
        
    def analyze_certificate(self, analysis):
        """
        Ejecutar análisis completo de un certificado
        """
        try:
            cert = analysis.certificado
            target = cert.ip or cert.url
            
            if cert.url:
                # Extraer hostname de URL
                parsed = urlparse(cert.url if cert.url.startswith('http') else f'https://{cert.url}')
                hostname = parsed.hostname or cert.url
            else:
                hostname = cert.ip
            
            # Ejecutar diferentes tipos de análisis
            if analysis.tipo in ['SSL_TLS', 'FULL']:
                self._analyze_ssl_certificate(analysis, hostname, cert.puerto)
                self._check_ssl_vulnerabilities(analysis, hostname, cert.puerto)
                self._run_external_analysis(analysis, hostname, cert.puerto)
                
            if analysis.tipo in ['WEB', 'FULL']:
                self._analyze_web_security(analysis, hostname, cert.puerto)
            
            # Marcar como exitoso
            return True
            
        except Exception as e:
            analysis.error_message = str(e)
            analysis.comentarios += f"\nError: {str(e)}"
            return False
    
    def _analyze_ssl_certificate(self, analysis, hostname, port):
        """
        Analizar certificado SSL y parámetros TLS
        """
        try:
            # Obtener certificado
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert_chain()[0]
                    cert_info = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
            # Crear parámetros generales
            self._create_general_params(analysis, cert_info)
            
            # Crear parámetros TLS
            self._create_tls_params(analysis, ssock, cipher)
            
            # Validar cadena de certificación
            self._validate_certificate_chain(analysis, hostname, port)
            
        except Exception as e:
            # Si falla SSL, intentar análisis básico con openssl
            self._fallback_openssl_analysis(analysis, hostname, port)
    
    def _create_general_params(self, analysis, cert_info):
        """
        Crear parámetros generales del certificado
        """
        # Extraer información del certificado
        subject_dict = dict(x[0] for x in cert_info.get('subject', []))
        issuer_dict = dict(x[0] for x in cert_info.get('issuer', []))
        
        # Fechas
        not_before = cert_info.get('notBefore', '')
        not_after = cert_info.get('notAfter', '')
        
        fecha_inicio = None
        fecha_fin = None
        
        try:
            if not_before:
                fecha_inicio = datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z').date()
            if not_after:
                fecha_fin = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z').date()
        except:
            pass
        
        # Calcular días restantes
        dias_restantes = None
        if fecha_fin:
            dias_restantes = (fecha_fin - date.today()).days
        
        # SANs
        san_list = []
        for san in cert_info.get('subjectAltName', []):
            if san[0] == 'DNS':
                san_list.append(san[1])
        
        ParametrosGenerales.objects.create(
            analisis=analysis,
            common_name=subject_dict.get('commonName', ''),
            san=json.dumps(san_list),
            issuer=issuer_dict.get('organizationName', ''),
            subject=subject_dict.get('organizationName', ''),
            serial_number=str(cert_info.get('serialNumber', '')),
            version=str(cert_info.get('version', '')),
            fecha_inicio=fecha_inicio,
            fecha_fin=fecha_fin,
            dias_restantes=dias_restantes
        )
    
    def _create_tls_params(self, analysis, ssock, cipher):
        """
        Crear parámetros TLS
        """
        # Información del cipher
        cipher_name = cipher[0] if cipher else ''
        protocol = cipher[1] if cipher else ''
        
        # Detectar versiones TLS soportadas
        tls_versions = self._check_tls_versions(analysis.certificado)
        
        ParametrosTLS.objects.create(
            analisis=analysis,
            protocolos=json.dumps([protocol] if protocol else []),
            cifrados_disponibles=json.dumps([cipher_name] if cipher_name else []),
            pfs=True,  # Asumir PFS por defecto con conexión exitosa
            sslv2_supported=tls_versions.get('sslv2', False),
            sslv3_supported=tls_versions.get('sslv3', False),
            tls10_supported=tls_versions.get('tls10', False),
            tls11_supported=tls_versions.get('tls11', False),
            tls12_supported=tls_versions.get('tls12', True),  # Asumir TLS 1.2
            tls13_supported=tls_versions.get('tls13', False)
        )
    
    def _check_tls_versions(self, certificate):
        """
        Verificar versiones TLS soportadas
        """
        hostname = certificate.ip or certificate.url
        port = certificate.puerto
        
        versions = {
            'sslv2': False,
            'sslv3': False,
            'tls10': False,
            'tls11': False,
            'tls12': False,
            'tls13': False
        }
        
        # Verificar TLS 1.2 (más común)
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.maximum_version = ssl.TLSVersion.TLSv1_2
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock) as ssock:
                    versions['tls12'] = True
        except:
            pass
        
        return versions
    
    def _check_ssl_vulnerabilities(self, analysis, hostname, port):
        """
        Verificar vulnerabilidades conocidas
        """
        vulnerabilities = []
        
        # Verificar certificado expirado
        try:
            params = analysis.parametros_generales
            if params and params.dias_restantes is not None:
                if params.dias_restantes < 0:
                    vulnerabilities.append({
                        'name': 'EXPIRED_CERT',
                        'severity': 'CRITICAL',
                        'description': f'Certificado expirado hace {abs(params.dias_restantes)} días'
                    })
                elif params.dias_restantes <= 30:
                    vulnerabilities.append({
                        'name': 'EXPIRING_CERT',
                        'severity': 'HIGH' if params.dias_restantes <= 7 else 'MEDIUM',
                        'description': f'Certificado expira en {params.dias_restantes} días'
                    })
        except:
            pass
        
        # Verificar protocolos débiles
        try:
            tls_params = analysis.parametros_tls
            if tls_params:
                if tls_params.sslv2_supported:
                    vulnerabilities.append({
                        'name': 'WEAK_PROTOCOL',
                        'severity': 'CRITICAL',
                        'description': 'SSLv2 soportado - protocolo inseguro'
                    })
                if tls_params.sslv3_supported:
                    vulnerabilities.append({
                        'name': 'POODLE',
                        'severity': 'HIGH',
                        'description': 'SSLv3 soportado - vulnerable a POODLE'
                    })
        except:
            pass
        
        # Crear registros de vulnerabilidades
        for vuln in vulnerabilities:
            Vulnerabilidades.objects.create(
                analisis=analysis,
                vulnerabilidad=vuln['name'],
                severity=vuln['severity'],
                description=vuln['description']
            )
    
    def _validate_certificate_chain(self, analysis, hostname, port):
        """
        Validar cadena de certificación
        """
        try:
            # Usar openssl para validar cadena
            cmd = [
                'openssl', 's_client', '-connect', f'{hostname}:{port}',
                '-verify_return_error', '-brief'
            ]
            
            result = subprocess.run(
                cmd, capture_output=True, text=True, 
                timeout=self.timeout, input=''
            )
            
            chain_ok = result.returncode == 0
            errors = not chain_ok
            
            # Detectar auto-firmado
            autofirmado = 'self signed' in result.stderr.lower()
            
            CadenaCertificacion.objects.create(
                analisis=analysis,
                cadena_ok=chain_ok,
                errores=errors,
                autofirmado=autofirmado,
                validation_errors=result.stderr[:500] if result.stderr else ''
            )
            
        except subprocess.TimeoutExpired:
            CadenaCertificacion.objects.create(
                analisis=analysis,
                cadena_ok=False,
                errores=True,
                validation_errors='Timeout en validación de cadena'
            )
        except Exception as e:
            CadenaCertificacion.objects.create(
                analisis=analysis,
                cadena_ok=False,
                errores=True,
                validation_errors=f'Error: {str(e)}'
            )
    
    def _analyze_web_security(self, analysis, hostname, port):
        """
        Analizar headers de seguridad web
        """
        try:
            import urllib.request
            
            url = f'https://{hostname}:{port}' if port != 443 else f'https://{hostname}'
            
            request = urllib.request.Request(url)
            request.add_header('User-Agent', 'Socrates-SSL-Analyzer/1.0')
            
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                headers = response.headers
                
                ParametrosWeb.objects.create(
                    analisis=analysis,
                    hsts='strict-transport-security' in headers,
                    expect_ct='expect-ct' in headers,
                    hpkp='public-key-pins' in headers,
                    sni=True,  # Asumir SNI si la conexión funcionó
                    ocsp_stapling=False,  # Requiere análisis más profundo
                    content_security_policy=headers.get('content-security-policy', ''),
                    x_frame_options=headers.get('x-frame-options', ''),
                    x_content_type_options=headers.get('x-content-type-options', ''),
                    referrer_policy=headers.get('referrer-policy', '')
                )
                
        except Exception as e:
            # Crear registro con valores por defecto
            ParametrosWeb.objects.create(
                analisis=analysis,
                hsts=False,
                expect_ct=False,
                hpkp=False,
                sni=None,
                ocsp_stapling=None
            )
    
    def _fallback_openssl_analysis(self, analysis, hostname, port):
        """
        Análisis de respaldo usando openssl command line
        """
        try:
            cmd = ['openssl', 's_client', '-connect', f'{hostname}:{port}', '-showcerts']
            
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self.timeout, input=''
            )
            
            if result.returncode == 0:
                # Extraer información básica del output
                output = result.stdout
                
                # Buscar información del certificado
                cert_match = re.search(r'subject=(.+)', output)
                issuer_match = re.search(r'issuer=(.+)', output)
                
                subject = cert_match.group(1) if cert_match else ''
                issuer = issuer_match.group(1) if issuer_match else ''
                
                ParametrosGenerales.objects.create(
                    analisis=analysis,
                    subject=subject[:255],
                    issuer=issuer[:255]
                )
                
        except Exception as e:
            pass
    
    def _run_external_analysis(self, analysis, hostname, port):
        """
        Ejecutar análisis con herramientas externas
        """
        try:
            # Análisis con herramientas externas
            nmap_results = self.external_analyzer.analyze_with_nmap(hostname, port)
            openssl_results = self.external_analyzer.analyze_with_openssl(hostname, port)
            
            # Verificaciones adicionales de vulnerabilidades
            external_vulns = self.external_analyzer.check_vulnerabilities(hostname, port)
            for vuln in external_vulns:
                Vulnerabilidades.objects.create(
                    analisis=analysis,
                    vulnerabilidad=vuln['name'],
                    severity=vuln['severity'],
                    description=vuln['description']
                )
            
            # Verificar Certificate Transparency
            ct_results = self.external_analyzer.check_certificate_transparency(hostname)
            
            # Verificar OCSP Stapling
            ocsp_results = self.external_analyzer.check_ocsp_stapling(hostname, port)
            
            # Actualizar parámetros web con resultados OCSP
            if hasattr(analysis, 'parametros_web') and analysis.parametros_web:
                web_params = analysis.parametros_web
                if 'ocsp_stapling' in ocsp_results:
                    web_params.ocsp_stapling = ocsp_results['ocsp_stapling']
                    web_params.save()
            
            # Guardar resultados en otros_parametros
            otros_params, created = OtrosParametros.objects.get_or_create(
                analisis=analysis,
                defaults={
                    'observaciones': json.dumps({
                        'nmap_results': nmap_results,
                        'openssl_advanced': openssl_results,
                        'ct_logs': ct_results,
                        'ocsp_stapling': ocsp_results
                    })
                }
            )
            
        except Exception as e:
            # Log error but don't fail the entire analysis
            analysis.comentarios += f"\nExternal analysis error: {str(e)}"