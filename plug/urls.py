from django.contrib import admin
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularSwaggerView,
    SpectacularRedocView
)

from . import views


# ========== Initialize Router ==========
router = DefaultRouter()

# User Management
router.register(r'users', views.UserViewSet, basename='user')

# Store Management
router.register(r'stores', views.StoreViewSet, basename='store')

# Storefront Management
router.register(r'templates', views.StorefrontTemplateViewSet, basename='template')
router.register(r'storefronts', views.StorefrontViewSet, basename='storefront')

# Product Management
router.register(r'categories', views.CategoryViewSet, basename='category')
router.register(r'products', views.ProductViewSet, basename='product')

# Order Management
router.register(r'orders', views.OrderViewSet, basename='order')
router.register(r'order-items', views.OrderItemViewSet, basename='orderitem')
router.register(r'returns', views.ReturnRequestViewSet, basename='return')

# Payment & Analytics
router.register(r'payments/gateways', views.PaymentGatewayViewSet, basename='gateway')
router.register(r'payments/transactions', views.TransactionViewSet, basename='transaction')
router.register(r'analytics', views.AnalyticsDataViewSet, basename='analytics')

# Integrations
router.register(r'integrations', views.IntegrationViewSet, basename='integration')

# ========== URL Patterns ==========
urlpatterns = [

    # Authentication
    path('api/auth/signup/', views.SignUpView.as_view(), name='signup'),
    path('api/auth/signin/', views.SignInView.as_view(), name='signin'),
    path('api/auth/verify-email/', views.VerifyEmailView.as_view(), name='verify-email'),
    path('api/auth/me/', views.UserProfileView.as_view(), name='user-profile'),
    # path('api/auth/login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/auth/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/auth/google/signin/', views.GoogleAuthView.as_view(), name='google-signin'),
    path('api/auth/google/signup/', views.GoogleAuthView.as_view(), name='google-signup'),
    
    # Admin
    path('admin/', admin.site.urls),
    
    # API
    path('api/', include(router.urls)),
    
   
    # path('auth/login/', LoginView.as_view(), name='login'),

    # Public Endpoints
    path('api/public/stores/<str:domain>/products/', views.PublicProductListView.as_view(), name='public-products'),
    path('api/public/stores/<str:domain>/products/<int:pk>/', views.PublicProductDetailView.as_view(), name='public-product-detail'),
    path('api/public/stores/<str:domain>/orders/', views.PublicOrderCreateView.as_view(), name='public-order-create'),
    
    # Documentation
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('api/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),

    path('api/auth/send-verification-email/', views.send_verification_email, name='send-verification-email'),
    path('api/auth/verify-email/<str:token>/', views.verify_email, name='verify-email'),



]