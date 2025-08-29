"""
Tareas de Celery para Notificaciones - Proyecto Sócrates
Sistema de Monitoreo SSL/TLS
"""

import logging
from datetime import datetime, timedelta
from typing import List
from celery import shared_task
from django.utils import timezone
from django.db.models import Q
from clients.models import Cliente
from certs.models import Certificado, VitalidadCertificado
from analysis.models import AnalisisSSL, Vulnerabilidad
from notifications.email_service import email_service

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3)
def check_certificate_expiration_alerts(self):
    """
    Verificar certificados próximos a expirar y enviar alertas
    """
    try:
        now = timezone.now()
        
        # Días para alertas (30, 14, 7, 1)
        alert_days = [30, 14, 7, 1]
        results = {'alerts_sent': 0, 'errors': 0}
        
        for days in alert_days:
            expiry_date = now + timedelta(days=days)
            
            # Buscar certificados que expiran en exactamente N días
            certificates = Certificado.objects.filter(
                fecha_expiracion__date=expiry_date.date(),
                fecha_expiracion__gte=now
            ).select_related('cliente')
            
            for certificate in certificates:
                try:
                    success = email_service.send_certificate_expiration_alert(
                        certificate, days
                    )
                    if success:
                        results['alerts_sent'] += 1
                        logger.info(f"Expiration alert sent for {certificate.get_target_display()} ({days} days)")
                    else:
                        results['errors'] += 1
                        logger.warning(f"Failed to send expiration alert for {certificate.get_target_display()}")
                        
                except Exception as e:
                    results['errors'] += 1
                    logger.error(f"Error sending expiration alert for {certificate.id}: {e}")
        
        logger.info(f"Certificate expiration check completed: {results}")
        return results
        
    except Exception as exc:
        logger.error(f"Error in certificate expiration check: {exc}")
        if self.request.retries < self.max_retries:
            raise self.retry(countdown=300, exc=exc)  # Retry in 5 minutes
        return {'error': str(exc)}


@shared_task(bind=True, max_retries=3)
def check_vulnerability_alerts(self):
    """
    Verificar análisis recientes con vulnerabilidades críticas y enviar alertas
    """
    try:
        # Buscar análisis de las últimas 24 horas con vulnerabilidades críticas
        cutoff_time = timezone.now() - timedelta(hours=24)
        
        critical_analyses = AnalisisSSL.objects.filter(
            fecha_fin__gte=cutoff_time,
            estado_analisis='COMPLETED',
            vulnerabilidades_encontradas__gt=0
        ).select_related('certificado', 'certificado__cliente')
        
        results = {'alerts_sent': 0, 'errors': 0}
        
        for analysis in critical_analyses:
            try:
                # Obtener vulnerabilidades críticas y altas
                critical_vulns = Vulnerabilidad.objects.filter(
                    analisis=analysis,
                    severity__in=['CRITICAL', 'HIGH']
                )
                
                if critical_vulns.exists():
                    success = email_service.send_vulnerability_alert(
                        analysis, list(critical_vulns)
                    )
                    if success:
                        results['alerts_sent'] += 1
                        logger.info(f"Vulnerability alert sent for analysis {analysis.id}")
                    else:
                        results['errors'] += 1
                        logger.warning(f"Failed to send vulnerability alert for analysis {analysis.id}")
                        
            except Exception as e:
                results['errors'] += 1
                logger.error(f"Error sending vulnerability alert for analysis {analysis.id}: {e}")
        
        logger.info(f"Vulnerability alerts check completed: {results}")
        return results
        
    except Exception as exc:
        logger.error(f"Error in vulnerability alerts check: {exc}")
        if self.request.retries < self.max_retries:
            raise self.retry(countdown=300, exc=exc)
        return {'error': str(exc)}


@shared_task(bind=True, max_retries=3)
def check_certificate_down_alerts(self):
    """
    Verificar certificados que han cambiado a estado inactivo y enviar alertas
    """
    try:
        # Buscar certificados que han cambiado a inactivo en las últimas 2 horas
        cutoff_time = timezone.now() - timedelta(hours=2)
        
        # Obtener vitalidades recientes con estado inactivo
        down_vitalities = VitalidadCertificado.objects.filter(
            fecha_verificacion__gte=cutoff_time,
            estado='inactivo'
        ).select_related('certificado', 'certificado__cliente')
        
        results = {'alerts_sent': 0, 'errors': 0}
        
        for vitality in down_vitalities:
            try:
                # Verificar si ya se envió una alerta reciente para este certificado
                recent_alert = VitalidadCertificado.objects.filter(
                    certificado=vitality.certificado,
                    fecha_verificacion__lt=vitality.fecha_verificacion,
                    fecha_verificacion__gte=cutoff_time - timedelta(hours=6),
                    estado='inactivo'
                ).exists()
                
                # Solo enviar si no hay alertas recientes
                if not recent_alert:
                    success = email_service.send_certificate_down_alert(
                        vitality.certificado, vitality
                    )
                    if success:
                        results['alerts_sent'] += 1
                        logger.info(f"Down alert sent for {vitality.certificado.get_target_display()}")
                    else:
                        results['errors'] += 1
                        logger.warning(f"Failed to send down alert for {vitality.certificado.get_target_display()}")
                        
            except Exception as e:
                results['errors'] += 1
                logger.error(f"Error sending down alert for certificate {vitality.certificado.id}: {e}")
        
        logger.info(f"Certificate down alerts check completed: {results}")
        return results
        
    except Exception as exc:
        logger.error(f"Error in certificate down alerts check: {exc}")
        if self.request.retries < self.max_retries:
            raise self.retry(countdown=300, exc=exc)
        return {'error': str(exc)}


@shared_task(bind=True, max_retries=2)
def send_weekly_summary_reports(self):
    """
    Enviar reportes semanales a todos los clientes
    """
    try:
        clients = Cliente.objects.all()
        results = {'reports_sent': 0, 'errors': 0}
        
        for client in clients:
            try:
                # Verificar si el cliente tiene certificados
                cert_count = Certificado.objects.filter(cliente=client).count()
                if cert_count == 0:
                    continue
                
                success = email_service.send_analysis_summary_report(client, period_days=7)
                if success:
                    results['reports_sent'] += 1
                    logger.info(f"Weekly summary sent to {client.name}")
                else:
                    results['errors'] += 1
                    logger.warning(f"Failed to send weekly summary to {client.name}")
                    
            except Exception as e:
                results['errors'] += 1
                logger.error(f"Error sending weekly summary to {client.name}: {e}")
        
        logger.info(f"Weekly summary reports completed: {results}")
        return results
        
    except Exception as exc:
        logger.error(f"Error in weekly summary reports: {exc}")
        if self.request.retries < self.max_retries:
            raise self.retry(countdown=1800, exc=exc)  # Retry in 30 minutes
        return {'error': str(exc)}


@shared_task(bind=True, max_retries=2)
def send_monthly_summary_reports(self):
    """
    Enviar reportes mensuales a todos los clientes
    """
    try:
        clients = Cliente.objects.all()
        results = {'reports_sent': 0, 'errors': 0}
        
        for client in clients:
            try:
                cert_count = Certificado.objects.filter(cliente=client).count()
                if cert_count == 0:
                    continue
                
                success = email_service.send_analysis_summary_report(client, period_days=30)
                if success:
                    results['reports_sent'] += 1
                    logger.info(f"Monthly summary sent to {client.name}")
                else:
                    results['errors'] += 1
                    logger.warning(f"Failed to send monthly summary to {client.name}")
                    
            except Exception as e:
                results['errors'] += 1
                logger.error(f"Error sending monthly summary to {client.name}: {e}")
        
        logger.info(f"Monthly summary reports completed: {results}")
        return results
        
    except Exception as exc:
        logger.error(f"Error in monthly summary reports: {exc}")
        if self.request.retries < self.max_retries:
            raise self.retry(countdown=3600, exc=exc)  # Retry in 1 hour
        return {'error': str(exc)}


@shared_task(bind=True)
def send_system_alert_task(alert_type: str, message: str, details: dict = None):
    """
    Enviar alerta del sistema de forma asíncrona
    """
    try:
        success = email_service.send_system_alert(alert_type, message, details)
        if success:
            logger.info(f"System alert sent: {alert_type}")
        else:
            logger.warning(f"Failed to send system alert: {alert_type}")
        return {'success': success}
        
    except Exception as exc:
        logger.error(f"Error sending system alert: {exc}")
        return {'error': str(exc)}


@shared_task(bind=True, max_retries=2)
def send_bulk_certificate_reports_task(client_ids: List[int] = None):
    """
    Enviar reportes masivos de certificados
    """
    try:
        if client_ids:
            certificates = Certificado.objects.filter(
                cliente_id__in=client_ids
            ).select_related('cliente')
        else:
            certificates = Certificado.objects.all().select_related('cliente')
        
        results = email_service.send_bulk_certificate_report(list(certificates))
        logger.info(f"Bulk certificate reports completed: {results}")
        return results
        
    except Exception as exc:
        logger.error(f"Error in bulk certificate reports: {exc}")
        if self.request.retries < self.max_retries:
            raise self.retry(countdown=1800, exc=exc)
        return {'error': str(exc)}


@shared_task
def test_email_notification(recipient_email: str):
    """
    Tarea para probar el sistema de notificaciones
    """
    try:
        from django.core.mail import send_mail
        from django.conf import settings
        
        subject = "✅ Test de Notificaciones - Sistema Sócrates"
        message = """
Este es un email de prueba del Sistema de Monitoreo SSL/TLS Sócrates.

Si recibes este mensaje, las notificaciones están funcionando correctamente.

Fecha y hora: {}
        """.format(timezone.now().strftime("%d/%m/%Y %H:%M:%S"))
        
        result = send_mail(
            subject=subject,
            message=message,
            from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@socrates.com'),
            recipient_list=[recipient_email],
            fail_silently=False
        )
        
        if result:
            logger.info(f"Test email sent successfully to {recipient_email}")
            return {'success': True, 'recipient': recipient_email}
        else:
            logger.warning(f"Test email failed to send to {recipient_email}")
            return {'success': False, 'recipient': recipient_email}
            
    except Exception as exc:
        logger.error(f"Error sending test email: {exc}")
        return {'error': str(exc), 'recipient': recipient_email}


# Tareas programadas (configurar en Django settings o Celery beat)
@shared_task
def daily_notification_checks():
    """
    Ejecutar todas las verificaciones diarias de notificaciones
    """
    results = {
        'expiration_check': None,
        'vulnerability_check': None,
        'down_check': None,
    }
    
    try:
        # Ejecutar verificaciones en paralelo
        results['expiration_check'] = check_certificate_expiration_alerts.delay()
        results['vulnerability_check'] = check_vulnerability_alerts.delay()
        results['down_check'] = check_certificate_down_alerts.delay()
        
        logger.info("Daily notification checks initiated")
        return results
        
    except Exception as exc:
        logger.error(f"Error initiating daily notification checks: {exc}")
        return {'error': str(exc)}