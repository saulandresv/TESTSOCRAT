from django.db import models

class Client(models.Model):
    name = models.CharField(max_length=255, unique=True)
    status = models.CharField(max_length=20, default="activo")  # activo|inactivo
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "clientes"
        ordering = ["name"]

    def __str__(self):
        return self.name
