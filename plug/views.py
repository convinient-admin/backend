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
from django.utils.text import slugify
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

class SignInView(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = CustomUserSerializer

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        # Authenticate by email instead of username
        user = None
        if email and password:
            try:
                existing_user = CustomUser.objects.get(email=email)
                user = authenticate(request, username=existing_user.username, password=password)
            except CustomUser.DoesNotExist:
                user = None

        if user is not None:
            if not user.is_verified:
                return Response(
                    {'error': 'Please verify your email before logging in.'},
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'user': self.get_serializer(user).data
            })
        else:
            return Response(
                {'error': 'Invalid credentials'},
                status=status.HTTP_401_UNAUTHORIZED
            )

class VerifyEmailView(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = CustomUserSerializer

    def get(self, request, token=None):
        if not token:
            return Response(
                {'error': 'Token is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
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
    
# ===== Password Reset =====
class ForgotPasswordView(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = CustomUserSerializer

    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({'status': 'error', 'message': 'Email is required'}, status=400)

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            # Do not reveal whether the email exists
            return Response({'status': 'success', 'message': 'If an account exists, a reset link has been sent'})

        # Reuse email_verification_token field to store one-time password reset token
        user.email_verification_token = str(uuid.uuid4())
        user.save()

        reset_url = f"{settings.FRONTEND_URL}/reset-password?token={user.email_verification_token}"

        subject = "Reset Your Password"
        message = f"""
        <html>
        <body>
            <p>We received a request to reset your password.</p>
            <p>Click the link below to set a new password:</p>
            <a href="{reset_url}" style="
                background-color: #4CAF50;
                color: white;
                padding: 10px 20px;
                text-decoration: none;
                border-radius: 5px;">Reset Password</a>
            <p>If you did not request this, you can safely ignore this email.</p>
        </body>
        </html>
        """

        try:
            with get_connection(
                host=settings.RESEND_SMTP_HOST,
                port=settings.RESEND_SMTP_PORT,
                username=settings.RESEND_SMTP_USERNAME,
                password=os.getenv("RESEND_API_KEY"),
                use_tls=True,
            ) as connection:
                email_msg = EmailMessage(
                    subject=subject,
                    body=message,
                    to=[user.email],
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    connection=connection
                )
                email_msg.content_subtype = "html"
                email_msg.send()
        except Exception:
            # Still respond success to avoid user enumeration and UX leakage
            pass

        return Response({'status': 'success', 'message': 'If an account exists, a reset link has been sent'})


class ResetPasswordView(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = CustomUserSerializer

    def post(self, request):
        token = request.data.get('token')
        new_password = request.data.get('new_password')
        if not token or not new_password:
            return Response({'status': 'error', 'message': 'token and new_password are required'}, status=400)

        try:
            user = CustomUser.objects.get(email_verification_token=token)
        except CustomUser.DoesNotExist:
            return Response({'status': 'error', 'message': 'Invalid or expired token'}, status=400)

        # Set new password and clear token
        user.set_password(new_password)
        user.email_verification_token = None
        user.save()

        return Response({'status': 'success', 'message': 'Password has been reset successfully'})


class SendVerificationEmailView(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = CustomUserSerializer

    def post(self, request):
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
                password=os.getenv("RESEND_API_KEY"),
                use_tls=True,
            ) as connection:
                email_msg = EmailMessage(
                    subject=subject,
                    body=message,
                    to=[user.email],
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    connection=connection
                )
                email_msg.content_subtype = "html"  # Set content type to HTML
                email_msg.send()
                
            return Response({"status": "success", "message": "Verification email sent"})
        
        except CustomUser.DoesNotExist:
            return Response({"status": "error", "message": "User not found"}, status=404)


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
        token = request.data.get('id_token')
        if not token:
            return Response(
                {'error': 'ID token is required.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Verify the ID token
            idinfo = id_token.verify_oauth2_token(
                token, google_requests.Request(), settings.GOOGLE_CLIENT_ID
            )

            email = idinfo['email']
            first_name = idinfo.get('given_name', '')
            last_name = idinfo.get('family_name', '')
            picture = idinfo.get('picture', '')

            # Helper to generate a unique username from email or name
            def generate_unique_username(email_value: str, first: str, last: str) -> str:
                base = email_value.split('@')[0] if email_value else f"{first}{last}".strip()
                base = slugify(base) or 'user'
                candidate = base
                counter = 0
                while CustomUser.objects.filter(username=candidate).exists():
                    counter += 1
                    candidate = f"{base}{counter}"
                return candidate

            # Check if user exists, or create a new one
            try:
                user = CustomUser.objects.get(email=email)
                # Update user info if needed
                if not user.first_name:
                    user.first_name = first_name
                if not user.last_name:
                    user.last_name = last_name
                if not user.profile_picture:
                    user.profile_picture = picture
                if not user.username:
                    user.username = generate_unique_username(email, first_name, last_name)
                user.auth_provider = 'google' # Ensure auth_provider is set
                user.is_verified = True # Ensure user is verified
                user.save()
            except CustomUser.DoesNotExist:
                user = CustomUser.objects.create(
                    email=email,
                    username=generate_unique_username(email, first_name, last_name),
                    first_name=first_name,
                    last_name=last_name,
                    profile_picture=picture,
                    is_verified=True,  # Google emails are pre-verified
                    auth_provider='google'
                )
                user.set_unusable_password()
                user.save()

            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)

            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'user': self.get_serializer(user).data,
                'message': 'Successfully authenticated with Google'
            }, status=status.HTTP_200_OK)

        except ValueError:
            # Invalid token
            return Response(
                {'error': 'Invalid or expired Google token.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            # Handle other exceptions
            return Response(
                {'error': f'An unexpected error occurred: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )