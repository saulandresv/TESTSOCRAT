import subprocess
import json
import socket
import ssl
from urllib.parse import urlparse
import requests
from datetime import datetime, timedelta
import re
import xml.etree.ElementTree as ET
try:
    from sslyze import Scanner, ServerScanRequest, ServerNetworkConfiguration
    from sslyze.plugins.scan_commands import ScanCommand
    SSLYZE_AVAILABLE = True
except ImportError:
    SSLYZE_AVAILABLE = False


class ExternalSSLAnalyzer:
    """
    Integración con herramientas externas para análisis SSL avanzado
    """
    
    def __init__(self):
        self.timeout = 10
    
    def analyze_with_nmap(self, hostname, port=443):
        """
        Análisis SSL con nmap
        """
        try:
            # Usar nmap para análisis SSL
            cmd = [
                'nmap', '--script', 'ssl-enum-ciphers,ssl-cert,ssl-date',
                '-p', str(port), hostname, '-oX', '-'
            ]
            
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self.timeout
            )
            
            if result.returncode == 0:
                return self._parse_nmap_output(result.stdout)
            else:
                return {'error': 'Nmap analysis failed', 'stderr': result.stderr}
                
        except subprocess.TimeoutExpired:
            return {'error': 'Nmap analysis timed out'}
        except Exception as e:
            return {'error': f'Nmap analysis error: {str(e)}'}
    
    def analyze_with_openssl(self, hostname, port=443):
        """
        Análisis avanzado con openssl
        """
        try:
            analyses = {}
            
            # Test diferentes versiones TLS
            tls_versions = {
                'tls1': '-tls1',
                'tls1_1': '-tls1_1', 
                'tls1_2': '-tls1_2',
                'tls1_3': '-tls1_3'
            }
            
            for version_name, version_flag in tls_versions.items():
                cmd = [
                    'openssl', 's_client', '-connect', f'{hostname}:{port}',
                    version_flag, '-brief', '-verify_return_error'
                ]
                
                try:
                    result = subprocess.run(
                        cmd, capture_output=True, text=True,
                        timeout=5, input=''
                    )
                    
                    analyses[version_name] = {
                        'supported': result.returncode == 0,
                        'output': result.stdout[:500] if result.stdout else '',
                        'error': result.stderr[:200] if result.stderr else ''
                    }
                except subprocess.TimeoutExpired:
                    analyses[version_name] = {'supported': False, 'error': 'Timeout'}
            
            # Test cipher suites
            analyses['cipher_scan'] = self._scan_cipher_suites(hostname, port)
            
            return analyses
            
        except Exception as e:
            return {'error': f'OpenSSL analysis error: {str(e)}'}
    
    def check_vulnerabilities(self, hostname, port=443):
        """
        Verificación de vulnerabilidades conocidas
        """
        vulnerabilities = []
        
        # Test Heartbleed
        if self._test_heartbleed(hostname, port):
            vulnerabilities.append({
                'name': 'HEARTBLEED',
                'severity': 'CRITICAL',
                'description': 'Server vulnerable to Heartbleed (CVE-2014-0160)'
            })
        
        # Test POODLE (SSLv3)
        if self._test_sslv3(hostname, port):
            vulnerabilities.append({
                'name': 'POODLE',
                'severity': 'HIGH',
                'description': 'SSLv3 enabled - vulnerable to POODLE attack'
            })
        
        # Test weak ciphers
        weak_ciphers = self._test_weak_ciphers(hostname, port)
        if weak_ciphers:
            vulnerabilities.append({
                'name': 'WEAK_CIPHER',
                'severity': 'MEDIUM',
                'description': f'Weak ciphers detected: {", ".join(weak_ciphers)}'
            })
        
        return vulnerabilities
    
    def _parse_nmap_output(self, xml_output):
        """
        Parse XML output from nmap
        """
        try:
            # Simple parsing - in production use xml.etree.ElementTree
            data = {
                'ssl_ciphers': [],
                'certificate_info': {},
                'vulnerabilities': []
            }
            
            if 'TLSv1.0' in xml_output:
                data['tls_versions'] = ['TLSv1.0']
            if 'TLSv1.1' in xml_output:
                data['tls_versions'].append('TLSv1.1')
            if 'TLSv1.2' in xml_output:
                data['tls_versions'].append('TLSv1.2')
            if 'TLSv1.3' in xml_output:
                data['tls_versions'].append('TLSv1.3')
            
            return data
        except Exception as e:
            return {'error': f'Failed to parse nmap output: {str(e)}'}
    
    def _scan_cipher_suites(self, hostname, port):
        """
        Scan available cipher suites
        """
        try:
            cmd = [
                'openssl', 'ciphers', '-V'
            ]
            
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                ciphers = []
                for line in result.stdout.split('\n'):
                    if line.strip():
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            ciphers.append(parts[2] if len(parts) > 2 else parts[1])
                
                return {'available_ciphers': ciphers[:20]}  # Limit output
            
            return {'error': 'Failed to get cipher list'}
            
        except Exception as e:
            return {'error': f'Cipher scan error: {str(e)}'}
    
    def _test_heartbleed(self, hostname, port):
        """
        Test for Heartbleed vulnerability
        """
        try:
            cmd = [
                'openssl', 's_client', '-connect', f'{hostname}:{port}',
                '-tlsextdebug'
            ]
            
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=5, input=''
            )
            
            # Simple heuristic - better tools would use actual exploit test
            return 'heartbeat' in result.stderr.lower()
            
        except:
            return False
    
    def _test_sslv3(self, hostname, port):
        """
        Test if SSLv3 is supported
        """
        try:
            cmd = [
                'openssl', 's_client', '-connect', f'{hostname}:{port}',
                '-ssl3'
            ]
            
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=5, input=''
            )
            
            return result.returncode == 0
            
        except:
            return False
    
    def _test_weak_ciphers(self, hostname, port):
        """
        Test for weak cipher suites
        """
        weak_ciphers = []
        
        weak_cipher_list = [
            'DES-CBC-SHA',
            'RC4-MD5',
            'EXP-DES-CBC-SHA',
            'EXP-RC4-MD5'
        ]
        
        for cipher in weak_cipher_list:
            try:
                cmd = [
                    'openssl', 's_client', '-connect', f'{hostname}:{port}',
                    '-cipher', cipher
                ]
                
                result = subprocess.run(
                    cmd, capture_output=True, text=True,
                    timeout=3, input=''
                )
                
                if result.returncode == 0:
                    weak_ciphers.append(cipher)
                    
            except:
                continue
        
        return weak_ciphers
    
    def check_certificate_transparency(self, hostname):
        """
        Verificar Certificate Transparency logs
        """
        try:
            # Simple CT log check using crt.sh API
            url = f'https://crt.sh/?q={hostname}&output=json'
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                ct_logs = response.json()
                return {
                    'ct_logs_found': len(ct_logs),
                    'recent_entries': [
                        {
                            'id': log.get('id'),
                            'issuer': log.get('issuer_name', ''),
                            'not_before': log.get('not_before', ''),
                            'not_after': log.get('not_after', '')
                        }
                        for log in ct_logs[:5]  # Last 5 entries
                    ]
                }
            else:
                return {'error': 'CT logs check failed'}
                
        except Exception as e:
            return {'error': f'CT check error: {str(e)}'}
    
    def check_ocsp_stapling(self, hostname, port=443):
        """
        Verificar OCSP Stapling
        """
        try:
            cmd = [
                'openssl', 's_client', '-connect', f'{hostname}:{port}',
                '-status', '-servername', hostname
            ]
            
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=10, input=''
            )
            
            has_ocsp = 'OCSP response:' in result.stdout
            ocsp_status = 'good' if 'Response Status: successful' in result.stdout else 'unknown'
            
            return {
                'ocsp_stapling': has_ocsp,
                'ocsp_status': ocsp_status if has_ocsp else None
            }
            
        except Exception as e:
            return {'error': f'OCSP check error: {str(e)}'}

    def analyze_with_sslscan(self, hostname, port=443):
        """
        Análisis completo con sslscan
        """
        try:
            cmd = [
                'sslscan', '--xml=-', '--no-colour',
                f'{hostname}:{port}'
            ]
            
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                return self._parse_sslscan_xml(result.stdout)
            else:
                return {'error': 'sslscan failed', 'stderr': result.stderr}
                
        except subprocess.TimeoutExpired:
            return {'error': 'sslscan timed out'}
        except Exception as e:
            return {'error': f'sslscan error: {str(e)}'}

    def _parse_sslscan_xml(self, xml_output):
        """
        Parsear salida XML de sslscan
        """
        try:
            root = ET.fromstring(xml_output)
            result = {
                'target': {},
                'ciphers': [],
                'protocols': {},
                'certificate': {},
                'vulnerabilities': []
            }

            # Información del target
            target = root.find('.//target')
            if target is not None:
                result['target'] = {
                    'host': target.get('host'),
                    'port': target.get('port')
                }

            # Protocolos soportados
            for protocol in root.findall('.//protocol'):
                proto_type = protocol.get('type')
                proto_version = protocol.get('version')
                enabled = protocol.get('enabled') == '1'
                
                if proto_type and proto_version:
                    key = f"{proto_type}{proto_version}"
                    result['protocols'][key] = enabled

            # Cifrados
            for cipher in root.findall('.//cipher'):
                cipher_data = {
                    'status': cipher.get('status'),
                    'sslversion': cipher.get('sslversion'),
                    'bits': cipher.get('bits'),
                    'cipher': cipher.get('cipher'),
                    'id': cipher.get('id')
                }
                result['ciphers'].append(cipher_data)

            # Información del certificado
            cert = root.find('.//certificate')
            if cert is not None:
                result['certificate'] = {
                    'subject': cert.find('.//subject').text if cert.find('.//subject') is not None else None,
                    'issuer': cert.find('.//issuer').text if cert.find('.//issuer') is not None else None,
                    'not_valid_before': cert.find('.//not-valid-before').text if cert.find('.//not-valid-before') is not None else None,
                    'not_valid_after': cert.find('.//not-valid-after').text if cert.find('.//not-valid-after') is not None else None,
                    'signature_algorithm': cert.find('.//signature-algorithm').text if cert.find('.//signature-algorithm') is not None else None,
                    'pk_algorithm': cert.find('.//pk-algorithm').text if cert.find('.//pk-algorithm') is not None else None,
                    'pk_bits': cert.find('.//pk-bits').text if cert.find('.//pk-bits') is not None else None
                }

            # Analizar vulnerabilidades basado en protocolos y cifrados
            self._detect_vulnerabilities_from_sslscan(result)

            return result

        except ET.ParseError as e:
            return {'error': f'Failed to parse sslscan XML: {str(e)}'}
        except Exception as e:
            return {'error': f'sslscan parsing error: {str(e)}'}

    def _detect_vulnerabilities_from_sslscan(self, result):
        """
        Detectar vulnerabilidades basándose en los datos de sslscan
        """
        vulnerabilities = []

        # Verificar protocolos inseguros
        if result['protocols'].get('SSLv2', False):
            vulnerabilities.append({
                'name': 'SSLV2_SUPPORTED',
                'severity': 'CRITICAL',
                'description': 'SSLv2 is supported - highly insecure protocol'
            })

        if result['protocols'].get('SSLv3', False):
            vulnerabilities.append({
                'name': 'POODLE',
                'severity': 'HIGH', 
                'description': 'SSLv3 is supported - vulnerable to POODLE attack'
            })

        # Verificar cifrados débiles
        weak_ciphers = []
        for cipher in result['ciphers']:
            if cipher['status'] == 'accepted':
                cipher_name = cipher.get('cipher', '').upper()
                
                # Cifrados conocidos como débiles
                if any(weak in cipher_name for weak in ['DES', 'RC4', 'MD5', 'NULL', 'EXPORT']):
                    weak_ciphers.append(cipher_name)

        if weak_ciphers:
            vulnerabilities.append({
                'name': 'WEAK_CIPHERS',
                'severity': 'MEDIUM',
                'description': f'Weak ciphers detected: {", ".join(set(weak_ciphers))}'
            })

        # Verificar longitudes de clave débiles
        short_key_ciphers = []
        for cipher in result['ciphers']:
            if cipher['status'] == 'accepted':
                bits = cipher.get('bits')
                if bits and int(bits) < 128:
                    short_key_ciphers.append(f"{cipher.get('cipher')} ({bits} bits)")

        if short_key_ciphers:
            vulnerabilities.append({
                'name': 'SHORT_KEY_LENGTH',
                'severity': 'HIGH',
                'description': f'Short key lengths detected: {", ".join(short_key_ciphers)}'
            })

        result['vulnerabilities'] = vulnerabilities

    def analyze_with_sslyze_advanced(self, hostname, port=443):
        """
        Análisis avanzado usando sslyze Python API
        """
        if not SSLYZE_AVAILABLE:
            return {'error': 'sslyze is not available'}

        try:
            # Configurar servidor para escaneo
            server_location = ServerNetworkConfiguration(hostname, port)
            scan_request = ServerScanRequest(
                server_location=server_location,
                scan_commands={
                    ScanCommand.TLS_1_3_SCAN,
                    ScanCommand.TLS_1_2_SCAN,
                    ScanCommand.TLS_1_1_SCAN,
                    ScanCommand.TLS_1_0_SCAN,
                    ScanCommand.SSL_3_0_SCAN,
                    ScanCommand.SSL_2_0_SCAN,
                    ScanCommand.CERTIFICATE_INFO,
                    ScanCommand.HEARTBLEED,
                    ScanCommand.OPENSSL_CCS_INJECTION,
                    ScanCommand.TLS_FALLBACK_SCSV,
                    ScanCommand.TLS_COMPRESSION,
                    ScanCommand.HTTP_HEADERS
                }
            )

            # Ejecutar escaneo
            scanner = Scanner()
            all_results = scanner.get_results()

            # Procesar resultados
            result = {
                'protocols': {},
                'certificate': {},
                'vulnerabilities': [],
                'cipher_suites': {},
                'headers': {}
            }

            for server_scan_result in scanner.get_results():
                if server_scan_result.server_location.hostname == hostname:
                    
                    # Protocolos TLS
                    for protocol in ['ssl_2_0', 'ssl_3_0', 'tls_1_0', 'tls_1_1', 'tls_1_2', 'tls_1_3']:
                        if hasattr(server_scan_result.scan_result, protocol + '_scan_result'):
                            proto_result = getattr(server_scan_result.scan_result, protocol + '_scan_result')
                            if proto_result:
                                result['protocols'][protocol] = {
                                    'is_protocol_supported': proto_result.is_protocol_supported,
                                    'cipher_suite_supported': len(proto_result.accepted_cipher_suites) if hasattr(proto_result, 'accepted_cipher_suites') else 0
                                }

                    # Información del certificado
                    if hasattr(server_scan_result.scan_result, 'certificate_info_scan_result'):
                        cert_result = server_scan_result.scan_result.certificate_info_scan_result
                        if cert_result and cert_result.certificate_deployments:
                            cert_deployment = cert_result.certificate_deployments[0]
                            leaf_cert = cert_deployment.received_certificate_chain[0]
                            
                            result['certificate'] = {
                                'common_name': leaf_cert.subject.get_attributes_for_oid(leaf_cert.subject.CN)[0].value if leaf_cert.subject.get_attributes_for_oid(leaf_cert.subject.CN) else None,
                                'issuer': str(leaf_cert.issuer),
                                'not_valid_before': str(leaf_cert.not_valid_before),
                                'not_valid_after': str(leaf_cert.not_valid_after),
                                'serial_number': str(leaf_cert.serial_number),
                                'signature_algorithm': leaf_cert.signature_algorithm_oid._name,
                                'public_key_size': leaf_cert.public_key().key_size,
                                'san_list': [str(name) for name in leaf_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value] if hasattr(leaf_cert, 'extensions') else []
                            }

                    # Vulnerabilidades
                    if hasattr(server_scan_result.scan_result, 'heartbleed_scan_result'):
                        heartbleed_result = server_scan_result.scan_result.heartbleed_scan_result
                        if heartbleed_result and heartbleed_result.is_vulnerable_to_heartbleed:
                            result['vulnerabilities'].append({
                                'name': 'HEARTBLEED',
                                'severity': 'CRITICAL',
                                'description': 'Server is vulnerable to Heartbleed attack'
                            })

                    if hasattr(server_scan_result.scan_result, 'openssl_ccs_injection_scan_result'):
                        ccs_result = server_scan_result.scan_result.openssl_ccs_injection_scan_result
                        if ccs_result and ccs_result.is_vulnerable_to_ccs_injection:
                            result['vulnerabilities'].append({
                                'name': 'CCS_INJECTION',
                                'severity': 'HIGH',
                                'description': 'Server is vulnerable to CCS Injection'
                            })

            return result

        except Exception as e:
            return {'error': f'sslyze advanced analysis error: {str(e)}'}

    def comprehensive_ssl_analysis(self, hostname, port=443):
        """
        Análisis SSL completo combinando todas las herramientas
        """
        results = {
            'timestamp': datetime.now().isoformat(),
            'target': f"{hostname}:{port}",
            'nmap': {},
            'sslscan': {},
            'sslyze': {},
            'openssl': {},
            'summary': {
                'protocols': {},
                'vulnerabilities': [],
                'certificate': {},
                'recommendations': []
            }
        }

        # Ejecutar análisis con cada herramienta
        try:
            results['nmap'] = self.analyze_with_nmap(hostname, port)
        except Exception as e:
            results['nmap'] = {'error': str(e)}

        try:
            results['sslscan'] = self.analyze_with_sslscan(hostname, port)
        except Exception as e:
            results['sslscan'] = {'error': str(e)}

        try:
            results['sslyze'] = self.analyze_with_sslyze_advanced(hostname, port)
        except Exception as e:
            results['sslyze'] = {'error': str(e)}

        try:
            results['openssl'] = self.analyze_with_openssl(hostname, port)
        except Exception as e:
            results['openssl'] = {'error': str(e)}

        # Consolidar resultados
        self._consolidate_analysis_results(results)

        return results

    def _consolidate_analysis_results(self, results):
        """
        Consolidar resultados de todas las herramientas en un resumen
        """
        summary = results['summary']
        
        # Consolidar protocolos
        all_protocols = {}
        
        # De sslscan
        if 'protocols' in results['sslscan']:
            for proto, enabled in results['sslscan']['protocols'].items():
                all_protocols[proto] = enabled

        # De sslyze
        if 'protocols' in results['sslyze']:
            for proto, data in results['sslyze']['protocols'].items():
                all_protocols[proto] = data.get('is_protocol_supported', False)

        summary['protocols'] = all_protocols

        # Consolidar vulnerabilidades
        all_vulnerabilities = []
        
        for tool in ['sslscan', 'sslyze', 'nmap']:
            if 'vulnerabilities' in results[tool]:
                all_vulnerabilities.extend(results[tool]['vulnerabilities'])

        # Remover duplicados
        unique_vulns = []
        seen_names = set()
        for vuln in all_vulnerabilities:
            if vuln['name'] not in seen_names:
                unique_vulns.append(vuln)
                seen_names.add(vuln['name'])

        summary['vulnerabilities'] = unique_vulns

        # Consolidar información del certificado
        cert_info = {}
        for tool in ['sslscan', 'sslyze']:
            if 'certificate' in results[tool] and results[tool]['certificate']:
                cert_info.update(results[tool]['certificate'])

        summary['certificate'] = cert_info

        # Generar recomendaciones
        recommendations = []
        
        if all_protocols.get('SSLv2', False):
            recommendations.append("Disable SSLv2 - it's highly insecure")
        
        if all_protocols.get('SSLv3', False):
            recommendations.append("Disable SSLv3 to prevent POODLE attacks")
        
        if not all_protocols.get('TLS1.2', False) and not all_protocols.get('TLS1.3', False):
            recommendations.append("Enable TLS 1.2 or 1.3 for better security")

        if any(vuln['severity'] == 'CRITICAL' for vuln in unique_vulns):
            recommendations.append("Address critical vulnerabilities immediately")

        summary['recommendations'] = recommendations