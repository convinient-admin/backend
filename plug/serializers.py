from rest_framework import serializers
from django.contrib.auth.hashers import make_password
from .models import (
    CustomUser, Store, StorefrontTemplate, Storefront,
    Category, Product, Order, OrderItem, ReturnRequest,
    PaymentGateway, Transaction, AnalyticsData, Integration
)

# ========== User Management ==========
from rest_framework import serializers
from django.contrib.auth.hashers import make_password
from .models import (
    CustomUser, Store, StorefrontTemplate, Storefront,
    Category, Product, Order, OrderItem, ReturnRequest,
    PaymentGateway, Transaction, AnalyticsData, Integration
)


# ========== Base Serializers ==========

class CustomUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    profile_picture = serializers.URLField(required=False, allow_blank=True)  # Optional field
    
    class Meta:
        model = CustomUser
        fields = [
            'id', 'username', 'email', 'password',
            'user_type', 'phone', 'company_name',
            'first_name', 'last_name', 'date_joined',
            'profile_picture',
        ]
        extra_kwargs = {
            'password': {'write_only': True},
            'user_type': {'default': 'customer'}
        }

    def create(self, validated_data):
        # Hash the password before creating user
        validated_data['password'] = make_password(validated_data.get('password'))
        return super().create(validated_data)

    def update(self, instance, validated_data):
        # Hash the password if it is supplied during update
        password = validated_data.pop('password', None)
        if password:
            instance.password = make_password(password)

        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance
    

class StoreSerializer(serializers.ModelSerializer):
    class Meta:
        model = Store
        fields = ['id', 'owner', 'name', 'domain', 'created_at', 'is_active']
        read_only_fields = ['created_at']

# ========== Detail Serializers ==========

class StoreDetailSerializer(StoreSerializer):
    owner = CustomUserSerializer(read_only=True)
    products = serializers.SerializerMethodField()
    categories = serializers.SerializerMethodField()
    storefront = serializers.SerializerMethodField()

    class Meta(StoreSerializer.Meta):
        fields = StoreSerializer.Meta.fields + ['owner', 'products', 'categories', 'storefront']

    def get_products(self, obj):
        products = obj.products.all()[:10]  # Limit to 10 products for performance
        return ProductSerializer(products, many=True).data

    def get_categories(self, obj):
        categories = obj.categories.all()
        return CategorySerializer(categories, many=True).data

    def get_storefront(self, obj):
        try:
            return StorefrontSerializer(obj.storefront).data
        except Storefront.DoesNotExist:
            return None

# ========== Other Serializers ==========
class StorefrontTemplateSerializer(serializers.ModelSerializer):
    class Meta:
        model = StorefrontTemplate
        fields = '__all__'

class StorefrontSerializer(serializers.ModelSerializer):
    class Meta:
        model = Storefront
        fields = '__all__'

class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = '__all__'

class ProductSerializer(serializers.ModelSerializer):
    # class Meta:
    #     model = Product
    #     fields = '__all__'
    
    class Meta:
        model = Product
        fields = [
            'id', 'store', 'name', 'description', 'price', 
            'categories', 'sku', 'inventory', 'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']

# ========== Order Management ==========
class OrderItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = OrderItem
        fields = ['id', 'order', 'product', 'quantity', 'price']

class OrderSerializer(serializers.ModelSerializer):
    items = OrderItemSerializer(many=True, read_only=True)
    
    class Meta:
        model = Order
        fields = [
            'id', 'store', 'customer', 'total', 
            'status', 'created_at', 'items'
        ]
        read_only_fields = ['created_at']

class ReturnRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReturnRequest
        fields = ['id', 'order', 'reason', 'status', 'created_at']
        read_only_fields = ['created_at']

# ========== Payment Integration ==========
class PaymentGatewaySerializer(serializers.ModelSerializer):
    class Meta:
        model = PaymentGateway
        fields = ['id', 'store', 'gateway_type', 'is_active']
        # Note: credentials are encrypted and not included in serializer

class TransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Transaction
        fields = ['id', 'order', 'gateway', 'amount', 'status', 'created_at']
        read_only_fields = ['created_at']

# ========== Analytics ==========
class AnalyticsDataSerializer(serializers.ModelSerializer):
    class Meta:
        model = AnalyticsData
        fields = ['id', 'store', 'metric', 'value', 'timestamp']
        read_only_fields = ['timestamp']

# ========== Third-Party Integrations ==========
class IntegrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Integration
        fields = ['id', 'store', 'service_type', 'config']
        # Note: credentials are encrypted and not included in serializer

# ========== Nested Serializers for Detailed Views ==========
class ProductDetailSerializer(ProductSerializer):
    categories = CategorySerializer(many=True, read_only=True)

class OrderDetailSerializer(OrderSerializer):
    items = OrderItemSerializer(many=True, read_only=True)
    customer = CustomUserSerializer(read_only=True)

class StoreSerializer(serializers.ModelSerializer):
    owner = serializers.PrimaryKeyRelatedField(queryset=CustomUser.objects.filter(user_type='merchant'))
    
    class Meta:
        model = Store
        fields = ['id', 'owner', 'name', 'domain', 'created_at', 'is_active']
        read_only_fields = ['created_at']