from django.db import models
from django.conf import settings

class UserClientAccess(models.Model):
    usuario = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE,
        verbose_name='Usuario'
    )
    cliente = models.ForeignKey(
        'clients.Client',
        on_delete=models.CASCADE,
        verbose_name='Cliente'
    )
    nivel_acceso = models.CharField(
        max_length=20,
        choices=[
            ('lectura', 'Lectura'),
            ('escritura', 'Escritura')
        ],
        verbose_name='Nivel de Acceso'
    )
    
    class Meta:
        unique_together = ('usuario', 'cliente')
        verbose_name = 'Acceso Usuario-Cliente'
        verbose_name_plural = 'Accesos Usuario-Cliente'
    
    def __str__(self):
        return f'{self.usuario.email} -> {self.cliente.nombre} ({self.nivel_acceso})'
