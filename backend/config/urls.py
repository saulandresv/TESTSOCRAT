from django.contrib import admin
from django.urls import path, include
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path("api/docs/", SpectacularSwaggerView.as_view(url_name="schema")),

    # API v1 - todas las rutas bajo el mismo prefijo
    path("api/v1/", include("accounts.urls")),
    path("api/v1/clients/", include("clients.url")),
    path("api/v1/analysis/", include("analysis.urls")),
    path("api/v1/reports/", include("reports.urls")),

    # Mantener compatibilidad con rutas antiguas
    path("api/certs/", include("certs.urls")),
]
