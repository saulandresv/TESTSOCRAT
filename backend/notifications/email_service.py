"""
Sistema de Notificaciones por Email - Proyecto Sócrates
Sistema de Monitoreo SSL/TLS
"""

import logging
from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta
from django.core.mail import send_mail, send_mass_mail, EmailMultiAlternatives
from django.template.loader import render_to_string
from django.conf import settings
from django.utils import timezone
from clients.models import Cliente
from certs.models import Certificado, VitalidadCertificado
from analysis.models import AnalisisSSL, Vulnerabilidad

logger = logging.getLogger(__name__)


class EmailNotificationService:
    """
    Servicio centralizado para el envío de notificaciones por email
    """
    
    def __init__(self):
        self.default_from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@socrates.com')
        self.admin_email = getattr(settings, 'ADMIN_EMAIL', 'admin@socrates.com')
    
    def send_certificate_expiration_alert(self, certificate: Certificado, days_until_expiry: int) -> bool:
        """
        Enviar alerta de expiración de certificado
        """
        try:
            subject = f"🚨 Certificado SSL expira en {days_until_expiry} días - {certificate.get_target_display()}"
            
            context = {
                'certificate': certificate,
                'days_until_expiry': days_until_expiry,
                'target': certificate.get_target_display(),
                'client_name': certificate.cliente.name,
                'expiry_date': certificate.fecha_expiracion,
                'dashboard_url': self._get_dashboard_url(),
                'certificate_url': self._get_certificate_url(certificate.id),
            }
            
            # Renderizar templates
            text_content = render_to_string('emails/certificate_expiry.txt', context)
            html_content = render_to_string('emails/certificate_expiry.html', context)
            
            # Lista de destinatarios
            recipients = [certificate.cliente.contact_email]
            if hasattr(certificate.cliente, 'notification_emails'):
                recipients.extend(certificate.cliente.notification_emails.split(','))
            
            return self._send_email(
                subject=subject,
                text_content=text_content,
                html_content=html_content,
                recipients=recipients,
                high_priority=days_until_expiry <= 7
            )
            
        except Exception as e:
            logger.error(f"Error sending certificate expiration alert: {e}")
            return False
    
    def send_vulnerability_alert(self, analysis: AnalisisSSL, critical_vulnerabilities: List[Vulnerabilidad]) -> bool:
        """
        Enviar alerta de vulnerabilidades críticas
        """
        try:
            vuln_count = len(critical_vulnerabilities)
            subject = f"🔴 {vuln_count} Vulnerabilidad(es) Crítica(s) - {analysis.certificado.get_target_display()}"
            
            context = {
                'analysis': analysis,
                'certificate': analysis.certificado,
                'vulnerabilities': critical_vulnerabilities,
                'vuln_count': vuln_count,
                'client_name': analysis.certificado.cliente.name,
                'analysis_date': analysis.fecha_fin or analysis.fecha_inicio,
                'security_score': analysis.puntuacion_seguridad,
                'dashboard_url': self._get_dashboard_url(),
                'analysis_url': self._get_analysis_url(analysis.id),
            }
            
            text_content = render_to_string('emails/vulnerability_alert.txt', context)
            html_content = render_to_string('emails/vulnerability_alert.html', context)
            
            recipients = [analysis.certificado.cliente.contact_email]
            
            return self._send_email(
                subject=subject,
                text_content=text_content,
                html_content=html_content,
                recipients=recipients,
                high_priority=True
            )
            
        except Exception as e:
            logger.error(f"Error sending vulnerability alert: {e}")
            return False
    
    def send_certificate_down_alert(self, certificate: Certificado, vitality: VitalidadCertificado) -> bool:
        """
        Enviar alerta cuando un certificado está inaccesible
        """
        try:
            subject = f"⚠️ Certificado SSL Inaccesible - {certificate.get_target_display()}"
            
            context = {
                'certificate': certificate,
                'vitality': vitality,
                'target': certificate.get_target_display(),
                'client_name': certificate.cliente.name,
                'check_time': vitality.fecha_verificacion,
                'error_message': vitality.mensaje_estado,
                'dashboard_url': self._get_dashboard_url(),
                'certificate_url': self._get_certificate_url(certificate.id),
            }
            
            text_content = render_to_string('emails/certificate_down.txt', context)
            html_content = render_to_string('emails/certificate_down.html', context)
            
            recipients = [certificate.cliente.contact_email]
            
            return self._send_email(
                subject=subject,
                text_content=text_content,
                html_content=html_content,
                recipients=recipients,
                high_priority=False
            )
            
        except Exception as e:
            logger.error(f"Error sending certificate down alert: {e}")
            return False
    
    def send_analysis_summary_report(self, client: Cliente, period_days: int = 7) -> bool:
        """
        Enviar resumen semanal/mensual de análisis
        """
        try:
            # Obtener datos del período
            end_date = timezone.now()
            start_date = end_date - timedelta(days=period_days)
            
            certificates = Certificado.objects.filter(cliente=client)
            analyses = AnalisisSSL.objects.filter(
                certificado__in=certificates,
                fecha_inicio__gte=start_date,
                fecha_inicio__lte=end_date
            ).order_by('-fecha_inicio')
            
            # Estadísticas
            total_analyses = analyses.count()
            successful_analyses = analyses.filter(estado_analisis='COMPLETED').count()
            failed_analyses = analyses.filter(estado_analisis='FAILED').count()
            
            # Vulnerabilidades por severidad
            vulnerabilities = Vulnerabilidad.objects.filter(
                analisis__in=analyses
            )
            
            vuln_stats = {
                'critical': vulnerabilities.filter(severity='CRITICAL').count(),
                'high': vulnerabilities.filter(severity='HIGH').count(),
                'medium': vulnerabilities.filter(severity='MEDIUM').count(),
                'low': vulnerabilities.filter(severity='LOW').count(),
            }
            
            # Certificados próximos a expirar
            expiring_soon = certificates.filter(
                fecha_expiracion__lte=end_date + timedelta(days=30),
                fecha_expiracion__gte=end_date
            ).order_by('fecha_expiracion')
            
            period_text = f"{'semanal' if period_days == 7 else 'mensual'}"
            subject = f"📊 Resumen {period_text} SSL/TLS - {client.name}"
            
            context = {
                'client': client,
                'period_days': period_days,
                'period_text': period_text,
                'start_date': start_date,
                'end_date': end_date,
                'total_certificates': certificates.count(),
                'total_analyses': total_analyses,
                'successful_analyses': successful_analyses,
                'failed_analyses': failed_analyses,
                'recent_analyses': analyses[:5],  # 5 más recientes
                'vuln_stats': vuln_stats,
                'expiring_certificates': expiring_soon,
                'dashboard_url': self._get_dashboard_url(),
            }
            
            text_content = render_to_string('emails/analysis_summary.txt', context)
            html_content = render_to_string('emails/analysis_summary.html', context)
            
            recipients = [client.contact_email]
            
            return self._send_email(
                subject=subject,
                text_content=text_content,
                html_content=html_content,
                recipients=recipients,
                high_priority=False
            )
            
        except Exception as e:
            logger.error(f"Error sending analysis summary report: {e}")
            return False
    
    def send_system_alert(self, alert_type: str, message: str, details: Dict[str, Any] = None) -> bool:
        """
        Enviar alerta del sistema a administradores
        """
        try:
            subject = f"🔧 Alerta del Sistema Sócrates - {alert_type}"
            
            context = {
                'alert_type': alert_type,
                'message': message,
                'details': details or {},
                'timestamp': timezone.now(),
                'server_info': self._get_server_info(),
            }
            
            text_content = render_to_string('emails/system_alert.txt', context)
            html_content = render_to_string('emails/system_alert.html', context)
            
            recipients = [self.admin_email]
            
            return self._send_email(
                subject=subject,
                text_content=text_content,
                html_content=html_content,
                recipients=recipients,
                high_priority=True
            )
            
        except Exception as e:
            logger.error(f"Error sending system alert: {e}")
            return False
    
    def send_bulk_certificate_report(self, certificates: List[Certificado]) -> Dict[str, int]:
        """
        Enviar reportes masivos a múltiples clientes
        """
        results = {'sent': 0, 'failed': 0}
        
        # Agrupar certificados por cliente
        certificates_by_client = {}
        for cert in certificates:
            client_id = cert.cliente.id
            if client_id not in certificates_by_client:
                certificates_by_client[client_id] = {
                    'client': cert.cliente,
                    'certificates': []
                }
            certificates_by_client[client_id]['certificates'].append(cert)
        
        # Enviar reporte a cada cliente
        for client_data in certificates_by_client.values():
            try:
                success = self._send_client_certificate_report(
                    client_data['client'],
                    client_data['certificates']
                )
                if success:
                    results['sent'] += 1
                else:
                    results['failed'] += 1
            except Exception as e:
                logger.error(f"Error sending bulk report to {client_data['client'].name}: {e}")
                results['failed'] += 1
        
        return results
    
    def _send_client_certificate_report(self, client: Cliente, certificates: List[Certificado]) -> bool:
        """
        Enviar reporte específico de certificados a un cliente
        """
        try:
            # Obtener últimos análisis de cada certificado
            cert_reports = []
            for cert in certificates:
                latest_analysis = AnalisisSSL.objects.filter(
                    certificado=cert
                ).order_by('-fecha_inicio').first()
                
                latest_vitality = VitalidadCertificado.objects.filter(
                    certificado=cert
                ).order_by('-fecha_verificacion').first()
                
                cert_reports.append({
                    'certificate': cert,
                    'analysis': latest_analysis,
                    'vitality': latest_vitality,
                    'status': self._get_certificate_status(cert, latest_analysis, latest_vitality)
                })
            
            subject = f"📋 Reporte de Certificados SSL/TLS - {client.name}"
            
            context = {
                'client': client,
                'certificate_reports': cert_reports,
                'report_date': timezone.now(),
                'dashboard_url': self._get_dashboard_url(),
            }
            
            text_content = render_to_string('emails/certificate_report.txt', context)
            html_content = render_to_string('emails/certificate_report.html', context)
            
            recipients = [client.contact_email]
            
            return self._send_email(
                subject=subject,
                text_content=text_content,
                html_content=html_content,
                recipients=recipients,
                high_priority=False
            )
            
        except Exception as e:
            logger.error(f"Error sending certificate report to {client.name}: {e}")
            return False
    
    def _send_email(
        self,
        subject: str,
        text_content: str,
        html_content: str,
        recipients: List[str],
        high_priority: bool = False
    ) -> bool:
        """
        Método interno para enviar emails con contenido HTML y texto
        """
        try:
            # Filtrar recipients vacíos
            valid_recipients = [email.strip() for email in recipients if email and email.strip()]
            if not valid_recipients:
                logger.warning(f"No valid recipients for email: {subject}")
                return False
            
            # Crear email multipart
            email = EmailMultiAlternatives(
                subject=subject,
                body=text_content,
                from_email=self.default_from_email,
                to=valid_recipients
            )
            
            # Agregar versión HTML
            email.attach_alternative(html_content, "text/html")
            
            # Headers adicionales
            if high_priority:
                email.extra_headers['X-Priority'] = '1'
                email.extra_headers['X-MSMail-Priority'] = 'High'
            
            # Enviar
            result = email.send()
            
            if result:
                logger.info(f"Email sent successfully: {subject} to {len(valid_recipients)} recipients")
            else:
                logger.warning(f"Failed to send email: {subject}")
            
            return bool(result)
            
        except Exception as e:
            logger.error(f"Error sending email '{subject}': {e}")
            return False
    
    def _get_certificate_status(
        self,
        certificate: Certificado,
        analysis: Optional[AnalisisSSL],
        vitality: Optional[VitalidadCertificado]
    ) -> Dict[str, Any]:
        """
        Obtener estado consolidado de un certificado
        """
        status = {
            'overall': 'unknown',
            'color': 'gray',
            'message': 'Estado desconocido'
        }
        
        # Verificar vitalidad
        if vitality:
            if vitality.estado == 'inactivo':
                status.update({
                    'overall': 'down',
                    'color': 'red',
                    'message': 'Certificado inaccesible'
                })
                return status
        
        # Verificar análisis
        if analysis:
            if analysis.vulnerabilidades_encontradas == 0:
                status.update({
                    'overall': 'good',
                    'color': 'green',
                    'message': 'Sin vulnerabilidades detectadas'
                })
            elif analysis.estado_general == 'CRITICAL_VULNERABILITIES':
                status.update({
                    'overall': 'critical',
                    'color': 'red',
                    'message': f'{analysis.vulnerabilidades_encontradas} vulnerabilidades críticas'
                })
            else:
                status.update({
                    'overall': 'warning',
                    'color': 'orange',
                    'message': f'{analysis.vulnerabilidades_encontradas} vulnerabilidades encontradas'
                })
        
        return status
    
    def _get_dashboard_url(self) -> str:
        """Obtener URL del dashboard"""
        base_url = getattr(settings, 'FRONTEND_URL', 'https://socrates.yourdomain.com')
        return f"{base_url}/dashboard"
    
    def _get_certificate_url(self, certificate_id: int) -> str:
        """Obtener URL de detalles del certificado"""
        base_url = getattr(settings, 'FRONTEND_URL', 'https://socrates.yourdomain.com')
        return f"{base_url}/certificates/{certificate_id}"
    
    def _get_analysis_url(self, analysis_id: int) -> str:
        """Obtener URL de detalles del análisis"""
        base_url = getattr(settings, 'FRONTEND_URL', 'https://socrates.yourdomain.com')
        return f"{base_url}/analysis/{analysis_id}"
    
    def _get_server_info(self) -> Dict[str, str]:
        """Obtener información básica del servidor"""
        import platform
        return {
            'hostname': platform.node(),
            'system': platform.system(),
            'python_version': platform.python_version(),
        }


# Instancia singleton del servicio
email_service = EmailNotificationService()