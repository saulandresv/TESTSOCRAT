from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView
from .views import LoginView, MFAVerifyView, MFASetupView, UserProfileView, MFASetupLoginView
from .viewsets import UserViewSet

# Router para ViewSets
router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')

urlpatterns = [
    # Autenticación
    path('auth/login/', LoginView.as_view(), name='login'),
    path('auth/mfa/verify/', MFAVerifyView.as_view(), name='mfa-verify'),
    path('auth/mfa/setup/', MFASetupView.as_view(), name='mfa-setup'),
    path('auth/mfa/setup-login/', MFASetupLoginView.as_view(), name='mfa-setup-login'),
    path('auth/refresh/', TokenRefreshView.as_view(), name='token-refresh'),
    path('auth/profile/', UserProfileView.as_view(), name='user-profile'),

    # ViewSets
    path('', include(router.urls)),
]