from celery import shared_task
from django.utils import timezone
from django.core.files.storage import default_storage
from django.core.mail import EmailMessage
from django.conf import settings
import os
import uuid
import logging

from .models import Report
from .generators import PDFReportGenerator, ExcelReportGenerator
from clients.models import Cliente

logger = logging.getLogger(__name__)


@shared_task
def generate_report_async(report_id):
    """
    Tarea asíncrona para generar reportes según especificaciones Proyecto Sócrates
    """
    try:
        report = Report.objects.get(id=report_id)
        report.status = 'PROCESSING'
        report.started_at = timezone.now()
        report.save()
        
        # Crear directorio de reportes si no existe
        reports_dir = os.path.join('media', 'reports', str(report.client.id))
        os.makedirs(reports_dir, exist_ok=True)
        
        # Generar nombre de archivo
        timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
        filename = f'{report.get_report_type_display()}_{report.client.name}_{timestamp}'
        
        if report.format == 'PDF':
            filename += '.pdf'
            generator = PDFReportGenerator(report.client, report.filters)
            
            if report.report_type == 'CERTIFICATE_DETAILED':
                file_path = os.path.join(reports_dir, filename)
                generator.generate_certificate_detailed_report(file_path)
            elif report.report_type == 'CLIENT_OVERVIEW':
                file_path = os.path.join(reports_dir, filename)
                generator.generate_client_summary_report(file_path)
            else:
                file_path = os.path.join(reports_dir, filename)
                generator.generate_certificate_detailed_report(file_path)  # Default
        
        elif report.format == 'EXCEL':
            filename += '.xlsx'
            generator = ExcelReportGenerator(report.client, report.filters)
            file_path = os.path.join(reports_dir, filename)
            generator.generate_client_detailed_excel(file_path)
        
        else:  # JSON
            filename += '.json'
            file_path = os.path.join(reports_dir, filename)
            generate_json_report(report, file_path)
        
        # Actualizar reporte con información del archivo
        report.file_path = file_path
        report.file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
        report.status = 'COMPLETED'
        report.completed_at = timezone.now()
        
        # Estadísticas del reporte
        certificates = generator.get_certificates_queryset() if hasattr(generator, 'get_certificates_queryset') else []
        analyses = generator.get_analyses_queryset() if hasattr(generator, 'get_analyses_queryset') else []
        
        report.total_certificates = certificates.count() if hasattr(certificates, 'count') else len(certificates)
        report.total_analyses = analyses.count() if hasattr(analyses, 'count') else len(analyses)
        
        if hasattr(analyses, 'filter'):  # QuerySet
            vulnerabilities = sum(a.vulnerabilidades.count() for a in analyses[:100])  # Limitar para evitar timeout
        else:
            vulnerabilities = 0
        
        report.total_vulnerabilities = vulnerabilities
        report.save()
        
        return {
            'report_id': str(report.id),
            'status': 'COMPLETED',
            'file_path': file_path,
            'file_size': report.file_size,
            'duration': report.duration
        }
        
    except Report.DoesNotExist:
        return {
            'report_id': str(report_id),
            'status': 'FAILED',
            'error': 'Report not found'
        }
    except Exception as e:
        # Actualizar reporte con error
        try:
            report.status = 'FAILED'
            report.error_message = str(e)
            report.completed_at = timezone.now()
            report.save()
        except:
            pass
        
        return {
            'report_id': str(report_id),
            'status': 'FAILED',
            'error': str(e)
        }


def generate_json_report(report, file_path):
    """Generar reporte en formato JSON"""
    import json
    from datetime import date
    
    from analysis.models import Analysis, Vulnerabilidades
    from certs.models import Certificate
    
    # Obtener datos según filtros
    certificates = Certificate.objects.filter(
        cliente=report.client,
        active=True
    )
    
    if report.filters.get('protocolo'):
        certificates = certificates.filter(protocolo=report.filters['protocolo'])
    
    data = {
        'report_info': {
            'id': str(report.id),
            'client': report.client.name,
            'type': report.report_type,
            'generated_at': timezone.now().isoformat(),
            'filters': report.filters
        },
        'summary': {
            'total_certificates': certificates.count(),
            'active_certificates': certificates.filter(analyses__otros_parametros__disponibilidad=True).distinct().count(),
        },
        'certificates': []
    }
    
    for cert in certificates:
        last_analysis = cert.analyses.filter(tuvo_exito=True).first()
        
        cert_data = {
            'id': cert.id,
            'target': cert.ip or cert.url,
            'port': cert.puerto,
            'protocol': cert.protocolo,
            'active': cert.active,
            'last_analysis': None
        }
        
        if last_analysis:
            analysis_data = {
                'id': last_analysis.id,
                'date': last_analysis.fecha_inicio.isoformat(),
                'success': last_analysis.tuvo_exito,
                'type': last_analysis.tipo,
                'general_params': None,
                'tls_params': None,
                'vulnerabilities': [],
                'chain_validation': None,
                'web_params': None,
                'other_params': None
            }
            
            # Parámetros generales según especificaciones
            if hasattr(last_analysis, 'parametros_generales') and last_analysis.parametros_generales:
                pg = last_analysis.parametros_generales
                analysis_data['general_params'] = {
                    'common_name': pg.common_name,
                    'san': pg.san,
                    'issuer': pg.issuer,
                    'subject': pg.subject,
                    'serial_number': pg.serial_number,
                    'version': pg.version,
                    'signature_algorithm': pg.algoritmo_firma,
                    'key_algorithm': pg.key_algorithm,
                    'key_size': pg.key_size,
                    'valid_from': pg.fecha_inicio.isoformat() if pg.fecha_inicio else None,
                    'valid_until': pg.fecha_fin.isoformat() if pg.fecha_fin else None,
                    'days_remaining': pg.dias_restantes,
                    'revocation_status': pg.estado_revocacion
                }
            
            # Parámetros TLS según especificaciones
            if hasattr(last_analysis, 'parametros_tls') and last_analysis.parametros_tls:
                tls = last_analysis.parametros_tls
                analysis_data['tls_params'] = {
                    'protocols_supported': {
                        'tls13': tls.tls13_supported,
                        'tls12': tls.tls12_supported,
                        'tls11': tls.tls11_supported,
                        'tls10': tls.tls10_supported,
                        'sslv3': tls.sslv3_supported,
                        'sslv2': tls.sslv2_supported
                    },
                    'available_ciphers': tls.cifrados_disponibles,
                    'weak_ciphers': tls.cifrados_debiles,
                    'perfect_forward_secrecy': tls.pfs
                }
            
            # Vulnerabilidades según especificaciones
            vulnerabilities = last_analysis.vulnerabilidades.all()
            for vuln in vulnerabilities:
                analysis_data['vulnerabilities'].append({
                    'name': vuln.vulnerabilidad,
                    'severity': vuln.severity,
                    'description': vuln.description
                })
            
            # Validación de cadena según especificaciones
            if hasattr(last_analysis, 'cadena_certificacion') and last_analysis.cadena_certificacion:
                cc = last_analysis.cadena_certificacion
                analysis_data['chain_validation'] = {
                    'chain_ok': cc.cadena_ok,
                    'has_errors': cc.errores,
                    'self_signed': cc.autofirmado,
                    'extra_intermediates': cc.intermedios_extra,
                    'validation_errors': cc.validation_errors
                }
            
            # Parámetros web según especificaciones
            if hasattr(last_analysis, 'parametros_web') and last_analysis.parametros_web:
                pw = last_analysis.parametros_web
                analysis_data['web_params'] = {
                    'hsts': pw.hsts,
                    'expect_ct': pw.expect_ct,
                    'hpkp': pw.hpkp,
                    'sni': pw.sni,
                    'ocsp_stapling': pw.ocsp_stapling,
                    'server_date': pw.fecha_hora_servidor.isoformat() if pw.fecha_hora_servidor else None
                }
            
            # Otros parámetros según especificaciones
            if hasattr(last_analysis, 'otros_parametros') and last_analysis.otros_parametros:
                op = last_analysis.otros_parametros
                analysis_data['other_params'] = {
                    'ssl_response_time': op.tiempo_respuesta_ssl,
                    'server_availability': op.disponibilidad,
                    'handshake_time': op.handshake_time_ms,
                    'observations': op.observaciones
                }
            
            cert_data['last_analysis'] = analysis_data
        
        data['certificates'].append(cert_data)
    
    # Escribir archivo JSON
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


@shared_task
def cleanup_old_reports():
    """Limpiar reportes antiguos (mantener solo últimos 90 días)"""
    from datetime import timedelta
    
    cutoff_date = timezone.now() - timedelta(days=90)
    
    old_reports = Report.objects.filter(
        created_at__lt=cutoff_date,
        status__in=['COMPLETED', 'FAILED']
    )
    
    # Eliminar archivos del sistema
    deleted_files = 0
    for report in old_reports:
        if report.file_path and os.path.exists(report.file_path):
            try:
                os.remove(report.file_path)
                deleted_files += 1
            except OSError:
                pass
    
    # Eliminar registros de base de datos
    count = old_reports.count()
    old_reports.delete()
    
    return {
        'deleted_reports': count,
        'deleted_files': deleted_files,
        'cutoff_date': cutoff_date.isoformat()
    }


@shared_task(bind=True)
def send_report_via_email(self, report_id, recipient_emails, include_summary=True):
    """
    Enviar reporte por email según especificaciones del Proyecto Sócrates
    """
    try:
        report = Report.objects.get(id=report_id)
        
        if report.status != 'COMPLETED':
            raise ValueError(f"Reporte no completado. Estado actual: {report.status}")
            
        if not report.file_path or not os.path.exists(report.file_path):
            raise FileNotFoundError("Archivo de reporte no encontrado")
        
        # Preparar contenido del email según especificaciones
        subject = f"Reporte de Certificados SSL/TLS - {report.client.name}"
        
        # Cuerpo del email con información del reporte
        body = f"""
Estimado/a usuario/a,

Se adjunta el reporte de monitoreo de certificados SSL/TLS según las especificaciones del Proyecto Sócrates.

DETALLES DEL REPORTE:
------------------------
Cliente: {report.client.name}
Tipo de Reporte: {report.get_report_type_display()}
Formato: {report.format}
Generado: {report.created_at.strftime('%d/%m/%Y %H:%M')}
Duración de Generación: {report.duration}
"""
        
        if include_summary and hasattr(report, 'total_certificates'):
            body += f"""

RESUMEN EJECUTIVO:
------------------
Total de Certificados: {report.total_certificates or 'N/A'}
Análisis Realizados: {report.total_analyses or 'N/A'}
Vulnerabilidades Detectadas: {report.total_vulnerabilities or 'N/A'}
Tamaño del Archivo: {report.file_size_mb} MB
"""
        
        body += f"""

Este reporte incluye todos los parámetros especificados en el Proyecto Sócrates:
• A) Parámetros Generales del Certificado
• B) Evaluación de Protocolos y Cifradores SSL/TLS  
• C) Vulnerabilidades Conocidas (Heartbleed, POODLE, DROWN, etc.)
• D) Validación e Integridad de la Cadena de Certificación
• E) Parámetros Específicos para SSH (cuando aplique)
• F) Parámetros adicionales relevantes para APIs y Web
• G) Otros parámetros Útiles (tiempo de respuesta, disponibilidad)

Para cualquier consulta sobre este reporte, no dude en contactarnos.

Saludos cordiales,
Sistema de Monitoreo SSL/TLS Sócrates
"""
        
        # Crear mensaje de email
        email = EmailMessage(
            subject=subject,
            body=body,
            from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@socrates.com'),
            to=recipient_emails if isinstance(recipient_emails, list) else [recipient_emails]
        )
        
        # Adjuntar archivo del reporte
        filename = f"Reporte_{report.client.name}_{report.created_at.strftime('%Y%m%d')}.{report.format.lower()}"
        
        with open(report.file_path, 'rb') as f:
            content_type = {
                'PDF': 'application/pdf',
                'EXCEL': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                'JSON': 'application/json'
            }.get(report.format, 'application/octet-stream')
            
            email.attach(filename, f.read(), content_type)
        
        # Enviar email
        email.send(fail_silently=False)
        
        logger.info(f"Reporte {report_id} enviado por email a {len(email.to)} destinatarios")
        
        return {
            'success': True,
            'report_id': str(report_id),
            'recipients': email.to,
            'filename': filename
        }
        
    except Report.DoesNotExist:
        error_msg = f"Reporte con ID {report_id} no encontrado"
        logger.error(error_msg)
        return {'error': error_msg}
        
    except Exception as exc:
        logger.error(f"Error enviando reporte por email: {exc}")
        return {'error': str(exc)}
