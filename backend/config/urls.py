from django.contrib import admin
from django.urls import path, include
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path("api/docs/", SpectacularSwaggerView.as_view(url_name="schema")),
    path("api/clients/", include("clients.url")),
    path("api/certs/", include("certs.urls")),
    path("api/v1/", include("accounts.urls")),
    path("api/analysis/", include("analysis.urls")),
]
