from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from .models import Analysis
from .analysis_engine import SSLAnalysisEngine
from certs.models import Certificate


@shared_task
def run_scheduled_analysis():
    """
    Ejecutar análisis programados para certificados activos
    """
    results = []
    
    # Obtener certificados que necesitan análisis (últimas 24 horas)
    recent_cutoff = timezone.now() - timedelta(hours=24)
    
    # Certificados sin análisis reciente
    certificates_needing_analysis = Certificate.objects.filter(
        active=True
    ).exclude(
        analyses__fecha_inicio__gte=recent_cutoff
    ).distinct()
    
    engine = SSLAnalysisEngine()
    
    for cert in certificates_needing_analysis[:10]:  # Limit to 10 certificates per run
        try:
            # Crear análisis programado
            analysis = Analysis.objects.create(
                certificado=cert,
                tipo='SSL_TLS',
                triggered_by='SCHEDULED',
                comentarios='Análisis programado automático'
            )
            
            # Ejecutar análisis
            success = engine.analyze_certificate(analysis)
            analysis.tuvo_exito = success
            analysis.fecha_fin = timezone.now()
            analysis.save()
            
            results.append({
                'certificate_id': cert.id,
                'analysis_id': analysis.id,
                'success': success,
                'target': cert.ip or cert.url
            })
            
        except Exception as e:
            results.append({
                'certificate_id': cert.id,
                'success': False,
                'error': str(e)
            })
    
    return {
        'processed': len(results),
        'results': results,
        'timestamp': timezone.now().isoformat()
    }


@shared_task
def analyze_certificate_async(certificate_id, analysis_type='SSL_TLS'):
    """
    Analizar certificado de forma asíncrona
    """
    try:
        cert = Certificate.objects.get(id=certificate_id, active=True)
        
        # Crear análisis
        analysis = Analysis.objects.create(
            certificado=cert,
            tipo=analysis_type,
            triggered_by='API',
            comentarios='Análisis asíncrono'
        )
        
        # Ejecutar análisis
        engine = SSLAnalysisEngine()
        success = engine.analyze_certificate(analysis)
        
        analysis.tuvo_exito = success
        analysis.fecha_fin = timezone.now()
        analysis.save()
        
        return {
            'certificate_id': certificate_id,
            'analysis_id': analysis.id,
            'success': success,
            'target': cert.ip or cert.url
        }
        
    except Certificate.DoesNotExist:
        return {
            'certificate_id': certificate_id,
            'success': False,
            'error': 'Certificate not found or inactive'
        }
    except Exception as e:
        return {
            'certificate_id': certificate_id,
            'success': False,
            'error': str(e)
        }


@shared_task
def cleanup_old_analysis():
    """
    Limpiar análisis antiguos (mantener solo los últimos 30 días)
    """
    cutoff_date = timezone.now() - timedelta(days=30)
    
    old_analyses = Analysis.objects.filter(
        fecha_inicio__lt=cutoff_date
    )
    
    count = old_analyses.count()
    old_analyses.delete()
    
    return {
        'deleted_count': count,
        'cutoff_date': cutoff_date.isoformat()
    }


@shared_task
def check_certificate_vitality():
    """
    Verificar vitalidad de todos los certificados activos
    """
    from certs.models import VitalityStatus
    import socket
    import ssl
    
    results = []
    certificates = Certificate.objects.filter(active=True)
    
    for cert in certificates:
        try:
            target = cert.ip or cert.url
            start_time = timezone.now()
            
            # Intentar conexión básica
            with socket.create_connection((target, cert.puerto), timeout=5) as sock:
                if cert.protocolo in ['HTTPS', 'TLS']:
                    # Para SSL/TLS, intentar handshake
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    with context.wrap_socket(sock, server_hostname=target) as ssock:
                        response_time = (timezone.now() - start_time).total_seconds() * 1000
                        
                        # Crear registro de vitalidad
                        VitalityStatus.objects.create(
                            certificado=cert,
                            estado='activo',
                            response_time_ms=int(response_time)
                        )
                        
                        results.append({
                            'certificate_id': cert.id,
                            'target': f"{target}:{cert.puerto}",
                            'status': 'up',
                            'response_time_ms': int(response_time)
                        })
                else:
                    # Para otros protocolos, solo verificar conexión
                    response_time = (timezone.now() - start_time).total_seconds() * 1000
                    
                    VitalityStatus.objects.create(
                        certificado=cert,
                        estado='activo',
                        response_time_ms=int(response_time)
                    )
                    
                    results.append({
                        'certificate_id': cert.id,
                        'target': f"{target}:{cert.puerto}",
                        'status': 'up',
                        'response_time_ms': int(response_time)
                    })
                    
        except Exception as e:
            # Crear registro de vitalidad con error
            VitalityStatus.objects.create(
                certificado=cert,
                estado='inactivo',
                error_message=str(e)[:500]
            )
            
            results.append({
                'certificate_id': cert.id,
                'target': f"{target}:{cert.puerto}",
                'status': 'down',
                'error': str(e)
            })
    
    return {
        'total_checked': len(results),
        'up': len([r for r in results if r['status'] == 'up']),
        'down': len([r for r in results if r['status'] == 'down']),
        'results': results,
        'timestamp': timezone.now().isoformat()
    }


@shared_task
def generate_certificate_expiry_alerts():
    """
    Generar alertas para certificados próximos a expirar
    """
    from django.core.mail import send_mail
    from django.conf import settings
    
    alerts = []
    warning_days = [30, 15, 7, 3, 1]  # Alertas en estos días antes de expirar
    
    today = timezone.now().date()
    
    for days in warning_days:
        expiry_date = today + timedelta(days=days)
        
        expiring_certs = Certificate.objects.filter(
            active=True,
            fecha_expiracion=expiry_date
        ).select_related('cliente')
        
        for cert in expiring_certs:
            target = cert.ip or cert.url
            alert_data = {
                'certificate_id': cert.id,
                'target': f"{target}:{cert.puerto}",
                'client': cert.cliente.name,
                'days_until_expiry': days,
                'expiry_date': cert.fecha_expiracion.isoformat()
            }
            
            alerts.append(alert_data)
            
            # Enviar email si está configurado
            if hasattr(settings, 'EMAIL_HOST') and settings.EMAIL_HOST:
                try:
                    subject = f'[Sócrates] Certificado expira en {days} días'
                    message = f"""
                    El certificado {target}:{cert.puerto} del cliente {cert.cliente.name} 
                    expira en {days} días (fecha: {cert.fecha_expiracion}).
                    
                    Por favor, renueve el certificado lo antes posible.
                    """
                    
                    # Aquí deberías obtener los emails de los administradores
                    send_mail(
                        subject,
                        message,
                        settings.DEFAULT_FROM_EMAIL,
                        ['admin@example.com'],  # Cambiar por emails reales
                        fail_silently=True,
                    )
                except Exception as e:
                    print(f"Error sending email alert: {e}")
    
    return {
        'total_alerts': len(alerts),
        'alerts': alerts,
        'timestamp': timezone.now().isoformat()
    }


@shared_task
def update_certificate_frequencies():
    """
    Actualizar fechas de próxima revisión basado en frecuencia configurada
    """
    certificates = Certificate.objects.filter(active=True)
    updated = 0
    
    for cert in certificates:
        # Si no tiene próxima revisión o ya pasó
        if not cert.fecha_proxima_revision or cert.fecha_proxima_revision <= timezone.now():
            next_revision = timezone.now() + timedelta(days=cert.frecuencia_analisis)
            cert.fecha_proxima_revision = next_revision
            cert.save()
            updated += 1
    
    return {
        'updated_certificates': updated,
        'timestamp': timezone.now().isoformat()
    }
