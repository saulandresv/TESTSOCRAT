from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import CertificateViewSet, VitalityStatusViewSet

router = DefaultRouter()
router.register(r'certificates', CertificateViewSet, basename='certificate')
router.register(r'vitality', VitalityStatusViewSet, basename='vitality')

urlpatterns = [
    path('', include(router.urls)),
]