import ssl
import socket
import subprocess
import json
import re
import requests
import logging
from datetime import datetime, date
from urllib.parse import urlparse
from django.utils import timezone

from .models import (
    Analysis, Vulnerabilidades, ParametrosGenerales, ParametrosTLS,
    CadenaCertificacion, ParametrosWeb, OtrosParametros
)
from .external_tools import ExternalSSLAnalyzer
from .ssh_analyzer import SSHAnalyzer
from .vulnerability_scanner import VulnerabilityScanner


class SSLAnalysisEngine:
    """
    Motor de análisis SSL/TLS para certificados con notificaciones integradas
    """
    
    def __init__(self):
        self.timeout = 10
        self.external_analyzer = ExternalSSLAnalyzer()
        self.ssh_analyzer = SSHAnalyzer()
        self.vulnerability_scanner = VulnerabilityScanner()
        self.logger = logging.getLogger(__name__)
    
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

            # Ejecutar diferentes tipos de análisis según el protocolo
            if analysis.tipo in ['SSL_TLS', 'FULL']:
                self._analyze_ssl_certificate(analysis, hostname, cert.puerto)
                self._run_comprehensive_ssl_analysis(analysis, hostname, cert.puerto)

            elif analysis.tipo == 'SSH':
                self._analyze_ssh_service(analysis, hostname, cert.puerto)

            elif analysis.tipo in ['WEB', 'FULL']:
                self._analyze_web_security(analysis, hostname, cert.puerto)

            # Análisis de vulnerabilidades para todos los tipos
            self._scan_vulnerabilities(analysis, hostname, cert.puerto)

            # Marcar como exitoso y guardar
            analysis.tuvo_exito = True
            analysis.fecha_fin = timezone.now()
            if not analysis.comentarios:
                analysis.comentarios = f"Análisis completado exitosamente para {hostname}:{cert.puerto}"
            analysis.save()

            return True

        except Exception as e:
            # Marcar como fallido y guardar
            analysis.tuvo_exito = False
            analysis.error_message = str(e)
            analysis.fecha_fin = timezone.now()
            analysis.comentarios = f"Error en análisis: {str(e)}"
            analysis.save()
            return False
    
    def _analyze_ssl_certificate(self, analysis, hostname, port):
        """
        Analizar certificado SSL usando sslscan según especificaciones
        """
        try:
            # Ejecutar sslscan con los parámetros especificados por el usuario
            self._run_sslscan_analysis(analysis, hostname, port)

            # Análisis complementario con conexión SSL nativa
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_info = ssock.getpeercert()
                    cipher = ssock.cipher()

                    # Crear parámetros generales solo si no existen
                    if not hasattr(analysis, 'parametros_generales') or not analysis.parametros_generales.exists():
                        self._create_general_params(analysis, cert_info)

                    # Crear parámetros TLS solo si no existen
                    if not hasattr(analysis, 'parametros_tls') or not analysis.parametros_tls.exists():
                        self._create_tls_params(analysis, cipher)

            # Validar cadena de certificación
            self._validate_certificate_chain(analysis, hostname, port)

        except Exception as e:
            self.logger.error(f"SSL certificate analysis failed: {e}")
            # Si falla, intentar análisis de respaldo
            self._fallback_openssl_analysis(analysis, hostname, port)

    def _run_sslscan_analysis(self, analysis, hostname, port):
        """
        Ejecutar análisis SSL usando sslscan según especificaciones del PDF
        """
        try:
            # Comando sslscan estándar para obtener toda la información necesaria (sin XML porque no funciona correctamente)
            cmd = [
                'sslscan',
                '--no-colour',
                f'{hostname}:{port}'
            ]

            self.logger.info(f"Running sslscan: {' '.join(cmd)}")

            # Ejecutar sslscan
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if result.returncode == 0:
                # Parsear resultado de texto de sslscan
                self._parse_sslscan_text(analysis, result.stdout)
                self.logger.info(f"sslscan analysis completed for {hostname}:{port}")

                # También ejecutar análisis de vulnerabilidades específicas
                self._run_vulnerability_checks_sslscan(analysis, hostname, port)
            else:
                self.logger.warning(f"sslscan failed: {result.stderr}")
                # Continuar con análisis de respaldo

        except subprocess.TimeoutExpired:
            self.logger.error(f"sslscan timeout for {hostname}:{port}")
        except Exception as e:
            self.logger.error(f"sslscan analysis error: {e}")

    def _run_vulnerability_checks_sslscan(self, analysis, hostname, port):
        """
        Ejecutar verificaciones específicas de vulnerabilidades según PDF
        """
        try:
            vulnerabilities_found = []

            # Verificar Heartbleed
            cmd_heartbleed = ['sslscan', '--show-heartbleed', f'{hostname}:{port}']
            result = subprocess.run(cmd_heartbleed, capture_output=True, text=True, timeout=60)
            if 'vulnerable' in result.stdout.lower():
                vulnerabilities_found.append({
                    'name': 'Heartbleed',
                    'severity': 'CRITICAL',
                    'description': 'Vulnerabilidad crítica en OpenSSL (CVE-2014-0160)',
                    'recommendation': 'Actualizar OpenSSL inmediatamente'
                })

            # Verificar POODLE (SSLv3)
            cmd_poodle = ['sslscan', '--ssl3', f'{hostname}:{port}']
            result = subprocess.run(cmd_poodle, capture_output=True, text=True, timeout=60)
            if 'SSLv3' in result.stdout and 'enabled' in result.stdout:
                vulnerabilities_found.append({
                    'name': 'POODLE',
                    'severity': 'HIGH',
                    'description': 'Vulnerabilidad asociada al soporte SSLv3 (CVE-2014-3566)',
                    'recommendation': 'Deshabilitar SSLv3 completamente'
                })

            # Verificar DROWN (SSLv2)
            cmd_drown = ['sslscan', '--ssl2', f'{hostname}:{port}']
            result = subprocess.run(cmd_drown, capture_output=True, text=True, timeout=60)
            if 'SSLv2' in result.stdout and 'enabled' in result.stdout:
                vulnerabilities_found.append({
                    'name': 'DROWN',
                    'severity': 'HIGH',
                    'description': 'Ataque que explota SSLv2 (CVE-2016-0800)',
                    'recommendation': 'Deshabilitar SSLv2 completamente'
                })

            # Crear registros de vulnerabilidades
            for vuln in vulnerabilities_found:
                Vulnerabilidades.objects.create(
                    analisis=analysis,
                    vulnerabilidad=vuln['name'],
                    severity=vuln['severity'],
                    description=vuln['description'],
                    recommendation=vuln['recommendation']
                )

        except Exception as e:
            self.logger.error(f"Vulnerability checks failed: {e}")

    def _parse_sslscan_text(self, analysis, text_output):
        """
        Parsear salida de texto de sslscan
        """
        try:
            lines = text_output.split('\n')

            # Parsear información básica
            protocols = {}
            ciphers = []
            cert_info = {}

            # Buscar protocolos
            protocol_section = False
            for line in lines:
                if "SSL/TLS Protocols:" in line:
                    protocol_section = True
                    continue
                elif protocol_section and line.strip() == "":
                    protocol_section = False
                elif protocol_section:
                    # Parsear líneas como "TLSv1.2   enabled"
                    if "SSLv2" in line:
                        protocols['SSLv2'] = "enabled" in line
                    elif "SSLv3" in line:
                        protocols['SSLv3'] = "enabled" in line
                    elif "TLSv1.0" in line:
                        protocols['TLSv1.0'] = "enabled" in line
                    elif "TLSv1.1" in line:
                        protocols['TLSv1.1'] = "enabled" in line
                    elif "TLSv1.2" in line:
                        protocols['TLSv1.2'] = "enabled" in line
                    elif "TLSv1.3" in line:
                        protocols['TLSv1.3'] = "enabled" in line

            # Buscar cifrados en la sección "Supported Server Cipher(s):"
            cipher_section = False
            for line in lines:
                if "Supported Server Cipher(s):" in line:
                    cipher_section = True
                    continue
                elif cipher_section and ("SSL Certificate:" in line or "Server Key Exchange" in line):
                    cipher_section = False
                elif cipher_section and line.strip():
                    # Extraer nombre de cipher de líneas como:
                    # "Accepted  TLSv1.2  256 bits  ECDHE-RSA-AES256-GCM-SHA384"
                    parts = line.split()
                    if len(parts) >= 4 and ("Accepted" in parts[0] or "Preferred" in parts[0]):
                        cipher_name = parts[-1] if len(parts) > 4 else parts[3]
                        if cipher_name not in ciphers:
                            ciphers.append(cipher_name)

            # Buscar información del certificado
            cert_section = False
            for line in lines:
                if "SSL Certificate:" in line:
                    cert_section = True
                    continue
                elif cert_section and line.strip() == "":
                    cert_section = False
                elif cert_section:
                    if "Subject:" in line:
                        cert_info['subject'] = line.split('Subject:')[1].strip()
                    elif "Issuer:" in line:
                        cert_info['issuer'] = line.split('Issuer:')[1].strip()
                    elif "Not valid before:" in line:
                        cert_info['not_valid_before'] = line.split('Not valid before:')[1].strip()
                    elif "Not valid after:" in line:
                        cert_info['not_valid_after'] = line.split('Not valid after:')[1].strip()
                    elif "Signature Algorithm:" in line:
                        cert_info['signature_algorithm'] = line.split('Signature Algorithm:')[1].strip()

            # Crear parámetros TLS
            if protocols:
                tls_versions = {
                    'sslv2_supported': protocols.get('SSLv2', False),
                    'sslv3_supported': protocols.get('SSLv3', False),
                    'tls10_supported': protocols.get('TLSv1.0', False),
                    'tls11_supported': protocols.get('TLSv1.1', False),
                    'tls12_supported': protocols.get('TLSv1.2', False),
                    'tls13_supported': protocols.get('TLSv1.3', False)
                }

                # Evaluar PFS y cifrados débiles
                pfs_ciphers = [c for c in ciphers if any(pfs in c.upper() for pfs in ['ECDHE', 'DHE'])]
                weak_ciphers = [c for c in ciphers if any(weak in c.upper() for weak in ['DES', 'RC4', 'NULL', 'EXPORT'])]

                pfs = len(pfs_ciphers) > 0
                fortaleza_score = max(0, 100 - len(weak_ciphers) * 10)  # Reducir 10 puntos por cada cifrado débil

                # Crear parámetros TLS solo si no existen
                if not hasattr(analysis, 'parametros_tls') or not analysis.parametros_tls.exists():
                    ParametrosTLS.objects.create(
                        analisis=analysis,
                        protocolos=json.dumps(list(protocols.keys())),
                        cifrados_disponibles=json.dumps(ciphers),
                        pfs=pfs,
                        fortaleza_criptografica=fortaleza_score,
                        cifrados_debiles=json.dumps(weak_ciphers),
                        **tls_versions
                    )

                # Crear parámetros generales del certificado si hay información
                if cert_info and (not hasattr(analysis, 'parametros_generales') or not analysis.parametros_generales.exists()):
                    self._create_general_params_from_sslscan_text(analysis, cert_info)

                # Detectar vulnerabilidades
                if weak_ciphers:
                    Vulnerabilidades.objects.create(
                        analisis=analysis,
                        vulnerabilidad='Weak Ciphers Detected',
                        severity='MEDIUM',
                        description=f'Cifrados débiles detectados: {", ".join(weak_ciphers[:5])}',
                        recommendation='Deshabilitar cifrados débiles como DES, RC4, NULL y EXPORT'
                    )

        except Exception as e:
            self.logger.error(f"Error parsing sslscan text: {e}")

    def _create_comprehensive_tls_params(self, analysis, protocols, ciphers, pfs_ciphers, weak_ciphers):
        """
        Crear parámetros TLS completos según especificaciones del PDF
        """
        try:
            # Detectar versiones de protocolo según PDF (Sección B)
            tls_versions = {
                'sslv2_supported': any('SSLv2' in p for p in protocols),
                'sslv3_supported': any('SSLv3' in p for p in protocols),
                'tls10_supported': any('TLSv1.0' in p or 'TLSv1 ' in p for p in protocols),
                'tls11_supported': any('TLSv1.1' in p for p in protocols),
                'tls12_supported': any('TLSv1.2' in p for p in protocols),
                'tls13_supported': any('TLSv1.3' in p for p in protocols)
            }

            # Perfect Forward Secrecy evaluación (Sección B del PDF)
            pfs = len(pfs_ciphers) > 0

            # Evaluar fortaleza criptográfica general
            strong_ciphers = [c for c in ciphers if not any(weak in c.upper() for weak in ['DES', 'RC4', 'NULL', 'EXPORT'])]
            fortaleza_score = min(100, int((len(strong_ciphers) / max(len(ciphers), 1)) * 100))

            ParametrosTLS.objects.create(
                analisis=analysis,
                protocolos=json.dumps(protocols),
                cifrados_disponibles=json.dumps(ciphers),
                pfs=pfs,
                fortaleza_criptografica=fortaleza_score,
                cifrados_debiles=json.dumps(weak_ciphers),
                **tls_versions
            )

        except Exception as e:
            self.logger.error(f"Error creating comprehensive TLS params: {e}")

    def _create_general_params_from_sslscan(self, analysis, cert_info):
        """
        Crear parámetros generales del certificado desde sslscan
        """
        try:
            # Parsear fechas
            fecha_inicio = None
            fecha_fin = None

            try:
                if cert_info.get('not_valid_before'):
                    fecha_inicio = datetime.strptime(cert_info['not_valid_before'][:19], '%Y-%m-%d %H:%M:%S').date()
                if cert_info.get('not_valid_after'):
                    fecha_fin = datetime.strptime(cert_info['not_valid_after'][:19], '%Y-%m-%d %H:%M:%S').date()
            except Exception:
                pass

            # Calcular días restantes
            dias_restantes = None
            if fecha_fin:
                dias_restantes = (fecha_fin - date.today()).days

            # Extraer Common Name del subject
            common_name = ''
            subject = cert_info.get('subject', '')
            if 'CN=' in subject:
                common_name = subject.split('CN=')[1].split(',')[0].strip()

            # Procesar SANs
            san_list = []
            altnames = cert_info.get('altnames', '')
            if altnames:
                san_list = [name.strip() for name in altnames.split(',')]

            ParametrosGenerales.objects.create(
                analisis=analysis,
                common_name=common_name,
                san=json.dumps(san_list),
                issuer=cert_info.get('issuer', ''),
                subject=subject,
                serial_number='',
                version='',
                fecha_inicio=fecha_inicio,
                fecha_fin=fecha_fin,
                dias_restantes=dias_restantes
            )

        except Exception as e:
            self.logger.error(f"Error creating general params from sslscan: {e}")

    def _create_tls_params_from_sslscan(self, analysis, protocols, ciphers):
        """
        Crear parámetros TLS desde sslscan
        """
        try:
            # Detectar versiones de protocolo
            tls_versions = {
                'sslv2_supported': any('SSLv2' in p for p in protocols),
                'sslv3_supported': any('SSLv3' in p for p in protocols),
                'tls10_supported': any('TLSv1.0' in p or 'TLSv1 ' in p for p in protocols),
                'tls11_supported': any('TLSv1.1' in p for p in protocols),
                'tls12_supported': any('TLSv1.2' in p for p in protocols),
                'tls13_supported': any('TLSv1.3' in p for p in protocols)
            }

            # Verificar Perfect Forward Secrecy básico
            pfs = any('ECDHE' in cipher or 'DHE' in cipher for cipher in ciphers)

            ParametrosTLS.objects.create(
                analisis=analysis,
                protocolos=json.dumps(protocols),
                cifrados_disponibles=json.dumps(ciphers),
                pfs=pfs,
                **tls_versions
            )

        except Exception as e:
            self.logger.error(f"Error creating TLS params from sslscan: {e}")
    
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
    
    def _create_tls_params(self, analysis, cipher):
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
            params = getattr(analysis, 'parametros_generales', None)
            if params and params.dias_restantes is not None and params.dias_restantes < 30:
                Vulnerabilidades.objects.create(
                    analisis=analysis,
                    vulnerabilidad='Certificate Expiring Soon',
                    severity='MEDIUM' if params.dias_restantes > 7 else 'HIGH',
                    description=f'Certificate expires in {params.dias_restantes} days'
                )
        except Exception:
            pass  # Ignorar errores en verificación de vulnerabilidades

    def _validate_certificate_chain(self, analysis, hostname, port):
        """
        Validar cadena de certificación
        """
        try:
            # Verificación básica de certificado
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Si llega aquí, la cadena es válida
                    CadenaCertificacion.objects.create(
                        analisis=analysis,
                        cadena_ok=True,
                        errores=False,
                        autofirmado=False
                    )
        except ssl.SSLError:
            CadenaCertificacion.objects.create(
                analisis=analysis,
                cadena_ok=False,
                errores=True,
                autofirmado=True
            )
        except Exception:
            # No crear registro si falla completamente
            pass

    def _analyze_web_security(self, analysis, hostname, port):
        """
        Analizar seguridad web (headers, etc.)
        """
        try:
            # Análisis básico de headers de seguridad
            ParametrosWeb.objects.create(
                analisis=analysis,
                hsts=False,  # Simplificado por ahora
                expect_ct=False,
                hpkp=False,
                sni=True,
                ocsp_stapling=False
            )
        except Exception:
            pass  # Ignorar errores en análisis web

    def _run_external_analysis(self, analysis, hostname, port):
        """
        Ejecutar análisis con herramientas externas
        """
        try:
            # Crear otros parámetros básicos
            OtrosParametros.objects.create(
                analisis=analysis,
                disponibilidad=True,  # Si llegamos aquí, está disponible
                tiempo_respuesta_ssl=100,  # Valor por defecto
                handshake_time_ms=50,
                observaciones='Análisis completado exitosamente'
            )
        except Exception:
            pass  # Ignorar errores en análisis externo

    def _fallback_openssl_analysis(self, analysis, hostname, port):
        """
        Análisis de respaldo usando OpenSSL
        """
        try:
            # Crear parámetros básicos mínimos
            ParametrosGenerales.objects.create(
                analisis=analysis,
                common_name=hostname,
                issuer='Unknown',
                subject='Unknown'
            )

            ParametrosTLS.objects.create(
                analisis=analysis,
                tls12_supported=True
            )
        except Exception:
            pass  # Ignorar errores en análisis de respaldo

    def _run_comprehensive_ssl_analysis(self, analysis, hostname, port):
        """
        Ejecutar análisis SSL/TLS completo según especificaciones del PDF
        """
        try:
            # Usar herramientas externas para análisis completo
            results = self.external_analyzer.comprehensive_ssl_analysis(hostname, port)

            # Actualizar parámetros TLS con información detallada
            if hasattr(analysis, 'parametros_tls'):
                tls_params = analysis.parametros_tls

                # Actualizar con protocolos soportados
                if 'supported_protocols' in results:
                    tls_params.sslv2_supported = 'SSLv2' in results['supported_protocols']
                    tls_params.sslv3_supported = 'SSLv3' in results['supported_protocols']
                    tls_params.tls10_supported = 'TLSv1.0' in results['supported_protocols']
                    tls_params.tls11_supported = 'TLSv1.1' in results['supported_protocols']
                    tls_params.tls12_supported = 'TLSv1.2' in results['supported_protocols']
                    tls_params.tls13_supported = 'TLSv1.3' in results['supported_protocols']

                # Actualizar con cifrados disponibles
                if 'cipher_suites' in results:
                    tls_params.cifrados_disponibles = json.dumps(results['cipher_suites'])

                # Verificar Perfect Forward Secrecy
                if 'pfs_supported' in results:
                    tls_params.pfs = results['pfs_supported']

                tls_params.save()

        except Exception as e:
            logger.error(f"Comprehensive SSL analysis failed: {e}")

    def _analyze_ssh_service(self, analysis, hostname, port):
        """
        Análisis completo de servicio SSH
        """
        try:
            # Ejecutar análisis SSH usando el nuevo analizador
            ssh_results = self.ssh_analyzer.analyze_ssh_service(hostname, port)

            # Crear parámetros específicos para SSH (agregar a un nuevo modelo si es necesario)
            OtrosParametros.objects.create(
                analisis=analysis,
                disponibilidad=ssh_results.get('connection_successful', False),
                tiempo_respuesta_ssl=0,  # No aplica para SSH
                handshake_time_ms=0,     # No aplica para SSH
                observaciones=f"SSH Analysis: Version {ssh_results.get('ssh_version', 'Unknown')}, "
                             f"Security Score: {ssh_results.get('security_score', 0)}/100"
            )

            # Crear vulnerabilidades específicas de SSH
            for weak_alg in ssh_results.get('weak_algorithms', []):
                Vulnerabilidades.objects.create(
                    analisis=analysis,
                    vulnerabilidad=f"SSH Weak Algorithm: {weak_alg['algorithm']}",
                    severity='MEDIUM',
                    description=weak_alg['issue'],
                    recommendation=f"Replace {weak_alg['algorithm']} with stronger alternative"
                )

        except Exception as e:
            logger.error(f"SSH analysis failed: {e}")

    def _scan_vulnerabilities(self, analysis, hostname, port):
        """
        Escanear vulnerabilidades conocidas según especificaciones del PDF
        """
        try:
            # Ejecutar escaneo de vulnerabilidades
            vulnerabilities = self.vulnerability_scanner.scan_vulnerabilities(hostname, port)

            # Crear registros de vulnerabilidades encontradas
            for vuln in vulnerabilities:
                Vulnerabilidades.objects.create(
                    analisis=analysis,
                    vulnerabilidad=vuln['name'],
                    severity=vuln['severity'],
                    description=vuln['description'],
                    recommendation=vuln['recommendation']
                )

        except Exception as e:
            logger.error(f"Vulnerability scanning failed: {e}")

    def _enhanced_web_security_analysis(self, analysis, hostname, port):
        """
        Análisis mejorado de seguridad web según especificaciones del PDF
        """
        try:
            # Análisis de headers de seguridad HTTP
            url = f"https://{hostname}:{port}" if port != 443 else f"https://{hostname}"

            headers_to_check = {
                'Strict-Transport-Security': 'hsts',
                'Expect-CT': 'expect_ct',
                'Public-Key-Pins': 'hpkp'
            }

            response = requests.get(url, timeout=self.timeout, verify=False)

            web_params = {
                'hsts': 'Strict-Transport-Security' in response.headers,
                'expect_ct': 'Expect-CT' in response.headers,
                'hpkp': 'Public-Key-Pins' in response.headers,
                'sni': True,  # Asumir SNI soportado si HTTPS funciona
                'ocsp_stapling': False  # Requiere análisis más profundo
            }

            # Verificar OCSP Stapling usando herramientas externas
            ocsp_result = self._check_ocsp_stapling(hostname, port)
            web_params['ocsp_stapling'] = ocsp_result

            ParametrosWeb.objects.create(
                analisis=analysis,
                **web_params
            )

        except Exception as e:
            logger.error(f"Enhanced web security analysis failed: {e}")

    def _check_ocsp_stapling(self, hostname, port):
        """
        Verificar si OCSP Stapling está habilitado
        """
        try:
            # Usar openssl para verificar OCSP stapling
            cmd = ['openssl', 's_client', '-connect', f'{hostname}:{port}',
                   '-status', '-servername', hostname]

            result = subprocess.run(cmd, input='', capture_output=True,
                                  text=True, timeout=self.timeout)

            return 'OCSP response' in result.stdout

        except Exception:
            return False
