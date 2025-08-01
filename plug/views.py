from rest_framework import viewsets, generics, permissions, status
from rest_framework.response import Response
from rest_framework.decorators import action,api_view
from django.shortcuts import get_object_or_404
from django.db.models import Q
from .models import (
    CustomUser, Store, StorefrontTemplate, Storefront,
    Category, Product, Order, OrderItem, ReturnRequest,
    PaymentGateway, Transaction, AnalyticsData, Integration
)
from .serializers import (
    CustomUserSerializer, StoreSerializer, StorefrontTemplateSerializer,
    StorefrontSerializer, CategorySerializer, ProductSerializer,
    OrderSerializer, OrderItemSerializer, ReturnRequestSerializer,
    PaymentGatewaySerializer, TransactionSerializer,
    AnalyticsDataSerializer, IntegrationSerializer,
    ProductDetailSerializer, OrderDetailSerializer, StoreDetailSerializer
)


from rest_framework.views import APIView
from rest_framework import status, permissions
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import CustomUserSerializer
from .models import CustomUser
from django.core.mail import send_mail,EmailMessage, get_connection
from django.conf import settings
import uuid
import os
from django.http import JsonResponse
import requests
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

class SignUpView(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = CustomUserSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            
            # Generate email verification token
            user.email_verification_token = str(uuid.uuid4())
            user.save()
            
            # Send verification email
            verification_url = f"{settings.FRONTEND_URL}/verify-email/{user.email_verification_token}/"
            send_mail(
                'Verify your email',
                f'Click this link to verify your email: {verification_url}',
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
            
            return Response(
                {'message': 'User created successfully. Please check your email to verify your account.'},
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

from .views import SignUpView, SignInView, GoogleSignUpView, GoogleSignInView

urlpatterns = [
    path('auth/signup/', SignUpView.as_view(), name='signup'),
    path('auth/signin/', SignInView.as_view(), name='signin'),
    path('auth/google/signup/', GoogleSignUpView.as_view(), name='google-signup'),
    path('auth/google/signin/', GoogleSignInView.as_view(), name='google-signin'),
]from .views import SignUpView, SignInView, GoogleSignUpView, GoogleSignInView

urlpatterns = [
    path('auth/signup/', SignUpView.as_view(), name='signup'),
    path('auth/signin/', SignInView.as_view(), name='signin'),
    path('auth/google/signup/', GoogleSignUpView.as_view(), name='google-signup'),
    path('auth/google/signin/', GoogleSignInView.as_view(), name='google-signin'),
]from .views import SignUpView, SignInView, GoogleSignUpView, GoogleSignInView

urlpatterns = [
    path('auth/signup/', SignUpView.as_view(), name='signup'),
    path('auth/signin/', SignInView.as_view(), name='signin'),
    path('auth/google/signup/', GoogleSignUpView.as_view(), name='google-signup'),
    path('auth/google/signin/', GoogleSignInView.as_view(), name='google-signin'),
]from .views import SignUpView, SignInView, GoogleSignUpView, GoogleSignInView

urlpatterns = [
    path('auth/signup/', SignUpView.as_view(), name='signup'),
    path('auth/signin/', SignInView.as_view(), name='signin'),
    path('auth/google/signup/', GoogleSignUpView.as_view(), name='google-signup'),
    path('auth/google/signin/', GoogleSignInView.as_view(), name='google-signin'),
]from .views import SignUpView, SignInView, GoogleSignUpView, GoogleSignInView

urlpatterns = [
    path('auth/signup/', SignUpView.as_view(), name='signup'),
    path('auth/signin/', SignInView.as_view(), name='signin'),
    path('auth/google/signup/', GoogleSignUpView.as_view(), name='google-signup'),
    path('auth/google/signin/', GoogleSignInView.as_view(), name='google-signin'),
]class VerifyEmailView(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = CustomUserSerializer

    def get(self, request, token):
        try:
            user = CustomUser.objects.get(email_verification_token=token)
            user.is_verified = True
            user.email_verification_token = None
            user.save()
            return Response({'message': 'Email successfully verified'})
        except CustomUser.DoesNotExist:
            return Response(
                {'error': 'Invalid verification token'},
                status=status.HTTP_400_BAD_REQUEST
            )

class UserProfileView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = CustomUserSerializer

    def get(self, request):
        return Response(self.get_serializer(request.user).data)
    
@api_view(['POST'])
def send_verification_email(request):
    email = request.data.get('email')
    
    try:
        user = CustomUser.objects.get(email=email)
        
        # Generate verification token if not exists
        if not user.email_verification_token:
            user.email_verification_token = str(uuid.uuid4())
            user.save()
        
        # Create verification link
        verification_url = f"{settings.FRONTEND_URL}/verify-email?token={user.email_verification_token}"
        
        subject = "Verify Your Email Address"
        message = f"""
        <html>
        <body>
            <h2>Welcome to Our Platform!</h2>
            <p>Please click the link below to verify your email address:</p>
            <a href="{verification_url}" style="
                background-color: #4CAF50;
                color: white;
                padding: 10px 20px;
                text-align: center;
                text-decoration: none;
                display: inline-block;
                border-radius: 5px;
            ">Verify Email</a>
            <p>If you didn't request this, please ignore this email.</p>
        </body>
        </html>
        """
        
        with get_connection(
            host=settings.RESEND_SMTP_HOST,
            port=settings.RESEND_SMTP_PORT,
            username=settings.RESEND_SMTP_USERNAME,
            password=os.environ.get("RESEND_API_KEY"),
            use_tls=True,
        ) as connection:
            email = EmailMessage(
                subject=subject,
                body=message,
                to=[user.email],
                from_email=settings.DEFAULT_FROM_EMAIL,
                connection=connection
            )
            email.content_subtype = "html"  # Set content type to HTML
            email.send()
            
        return Response({"status": "success", "message": "Verification email sent"})
    
    except CustomUser.DoesNotExist:
        return Response({"status": "error", "message": "User not found"}, status=404)
@api_view(['GET'])
def verify_email(request, token):
    try:
        user = CustomUser.objects.get(email_verification_token=token)
        user.is_verified = True
        user.email_verification_token = None
        user.save()
        return Response({"status": "success", "message": "Email successfully verified"})
    except CustomUser.DoesNotExist:
        return Response({"status": "error", "message": "Invalid verification token"}, status=400)


# ========== Custom Permissions ==========
class IsStoreOwner(permissions.BasePermission):
    """Check if user is the owner of the store"""
    def has_object_permission(self, request, view, obj):
        if hasattr(obj, 'owner'):
            return obj.owner == request.user
        elif hasattr(obj, 'store'):
            return obj.store.owner == request.user
        return False

class IsAdminOrStoreOwner(permissions.BasePermission):
    """Allow access to admin users or store owners"""
    def has_permission(self, request, view):
        return request.user.is_authenticated and (
            request.user.is_staff or request.user.user_type == 'merchant'
        )

    def has_object_permission(self, request, view, obj):
        return request.user.is_staff or (
            hasattr(obj, 'owner') and obj.owner == request.user
        )

# ========== User Management ==========
class UserViewSet(viewsets.ModelViewSet):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    permission_classes = [permissions.IsAdminUser]

    @action(detail=False, methods=['get'], permission_classes=[permissions.IsAuthenticated])
    def me(self, request):
        serializer = self.get_serializer(request.user)
        return Response(serializer.data)

# ========== Store Management ==========
class StoreViewSet(viewsets.ModelViewSet):
    serializer_class = StoreSerializer
    permission_classes = [IsAdminOrStoreOwner]

    def get_queryset(self):
        user = self.request.user
        if user.is_staff:
            return Store.objects.all()
        return Store.objects.filter(owner=user)

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return StoreDetailSerializer
        return super().get_serializer_class()

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)

    @action(detail=True, methods=['get'])
    def analytics(self, request, pk=None):
        store = self.get_object()
        analytics = AnalyticsData.objects.filter(store=store)
        serializer = AnalyticsDataSerializer(analytics, many=True)
        return Response(serializer.data)

# ========== Storefront Management ==========
class StorefrontTemplateViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = StorefrontTemplate.objects.all()
    serializer_class = StorefrontTemplateSerializer
    permission_classes = [permissions.IsAuthenticated]

class StorefrontViewSet(viewsets.ModelViewSet):
    serializer_class = StorefrontSerializer
    permission_classes = [IsStoreOwner]

    def get_queryset(self):
        return Storefront.objects.filter(store__owner=self.request.user)

    def perform_create(self, serializer):
        store = serializer.validated_data['store']
        if store.owner != self.request.user:
            raise permissions.PermissionDenied("You don't own this store")
        serializer.save()

# ========== Product Management ==========
class CategoryViewSet(viewsets.ModelViewSet):
    serializer_class = CategorySerializer
    permission_classes = [IsStoreOwner]

    def get_queryset(self):
        return Category.objects.filter(store__owner=self.request.user)

    def perform_create(self, serializer):
        store = serializer.validated_data['store']
        if store.owner != self.request.user:
            raise permissions.PermissionDenied("You don't own this store")
        serializer.save()

class ProductViewSet(viewsets.ModelViewSet):
    permission_classes = [IsStoreOwner]

    def get_queryset(self):
        return Product.objects.filter(store__owner=self.request.user)

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return ProductDetailSerializer
        return ProductSerializer

    def perform_create(self, serializer):
        store = serializer.validated_data['store']
        if store.owner != self.request.user:
            raise permissions.PermissionDenied("You don't own this store")
        serializer.save()

    @action(detail=False, methods=['get'])
    def search(self, request):
        query = request.query_params.get('q', '')
        products = Product.objects.filter(
            Q(name__icontains=query) | 
            Q(description__icontains=query),
            store__owner=request.user
        )
        serializer = self.get_serializer(products, many=True)
        return Response(serializer.data)

# ========== Order Management ==========
class OrderViewSet(viewsets.ModelViewSet):
    permission_classes = [IsStoreOwner]

    def get_queryset(self):
        return Order.objects.filter(store__owner=self.request.user)

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return OrderDetailSerializer
        return OrderSerializer

    @action(detail=True, methods=['post'])
    def process(self, request, pk=None):
        order = self.get_object()
        if order.status != 'pending':
            return Response(
                {'error': 'Order already processed'},
                status=status.HTTP_400_BAD_REQUEST
            )
        order.status = 'processing'
        order.save()
        return Response({'status': 'Order is being processed'})

    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        order = self.get_object()
        if order.status not in ['pending', 'processing']:
            return Response(
                {'error': 'Order cannot be canceled at this stage'},
                status=status.HTTP_400_BAD_REQUEST
            )
        order.status = 'canceled'
        order.save()
        return Response({'status': 'Order canceled'})

class OrderItemViewSet(viewsets.ModelViewSet):
    serializer_class = OrderItemSerializer
    permission_classes = [IsStoreOwner]

    def get_queryset(self):
        return OrderItem.objects.filter(order__store__owner=self.request.user)

class ReturnRequestViewSet(viewsets.ModelViewSet):
    serializer_class = ReturnRequestSerializer
    permission_classes = [IsStoreOwner]

    def get_queryset(self):
        return ReturnRequest.objects.filter(order__store__owner=self.request.user)

# ========== Payment & Analytics ==========
class PaymentGatewayViewSet(viewsets.ModelViewSet):
    serializer_class = PaymentGatewaySerializer
    permission_classes = [IsStoreOwner]

    def get_queryset(self):
        return PaymentGateway.objects.filter(store__owner=self.request.user)

class TransactionViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = TransactionSerializer
    permission_classes = [IsStoreOwner]

    def get_queryset(self):
        return Transaction.objects.filter(order__store__owner=self.request.user)

class AnalyticsDataViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = AnalyticsDataSerializer
    permission_classes = [IsStoreOwner]

    def get_queryset(self):
        return AnalyticsData.objects.filter(store__owner=self.request.user)

# ========== Integrations ==========
class IntegrationViewSet(viewsets.ModelViewSet):
    serializer_class = IntegrationSerializer
    permission_classes = [IsStoreOwner]

    def get_queryset(self):
        return Integration.objects.filter(store__owner=self.request.user)

# ========== Customer-Facing Views ==========
class PublicProductListView(generics.ListAPIView):
    serializer_class = ProductSerializer
    permission_classes = [permissions.AllowAny]

    def get_queryset(self):
        store_domain = self.kwargs['store_domain']
        return Product.objects.filter(
            store__domain=store_domain,
            store__is_active=True
        )

class PublicProductDetailView(generics.RetrieveAPIView):
    serializer_class = ProductDetailSerializer
    permission_classes = [permissions.AllowAny]

    def get_object(self):
        store_domain = self.kwargs['store_domain']
        product_id = self.kwargs['pk']
        return get_object_or_404(
            Product,
            pk=product_id,
            store__domain=store_domain,
            store__is_active=True
        )

class PublicOrderCreateView(generics.CreateAPIView):
    serializer_class = OrderSerializer
    permission_classes = [permissions.AllowAny]

    def perform_create(self, serializer):
        store_domain = self.kwargs['store_domain']
        store = get_object_or_404(Store, domain=store_domain, is_active=True)
        serializer.save(store=store, status='pending')

class GoogleAuthView(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = CustomUserSerializer

    def post(self, request):
        try:
            # Get the token from the request
            token = request.data.get('access_token')  # Changed from 'token' to 'access_token'
            
            # Get user info from Google
            response = requests.get(
                'https://www.googleapis.com/oauth2/v3/userinfo',
                headers={'Authorization': f'Bearer {token}'}
            )
            
            if response.status_code != 200:
                return Response(
                    {'error': 'Failed to get user info from Google'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            user_info = response.json()
            email = user_info['email']
            first_name = user_info.get('given_name', '')
            last_name = user_info.get('family_name', '')
            picture = user_info.get('picture', '')
            
            # Check if user exists
            try:
                user = CustomUser.objects.get(email=email)
                # Update user info if needed
                if not user.first_name:
                    user.first_name = first_name
                if not user.last_name:
                    user.last_name = last_name
                if not user.profile_picture:
                    user.profile_picture = picture
                user.save()
            except CustomUser.DoesNotExist:
                # Create new user if doesn't exist
                user = CustomUser.objects.create(
                    email=email,
                    first_name=first_name,
                    last_name=last_name,
                    profile_picture=picture,
                    is_verified=True,  # Google emails are pre-verified
                    auth_provider='google'
                )
                user.set_unusable_password()  # Since they'll use Google to login
                user.save()

            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'user': self.get_serializer(user).data,
                'message': 'Successfully authenticated with Google'
            })

        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )