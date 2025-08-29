"""
URLs para módulo de reportes - Proyecto Sócrates
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import ReportViewSet, get_report_templates

router = DefaultRouter()
router.register(r'', ReportViewSet, basename='reports')

urlpatterns = [
    path('templates/', get_report_templates, name='report-templates'),
    path('', include(router.urls)),
]