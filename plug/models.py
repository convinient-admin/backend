from django.db import models
from django.contrib.auth.models import AbstractUser
from django_cryptography.fields import encrypt

# ========== User Management ==========
class CustomUser(AbstractUser):
    USER_TYPE_CHOICES = (
        ('merchant', 'Merchant'),
        ('customer', 'Customer'),
        ('admin', 'Admin'),
    )
    user_type = models.CharField(max_length=20, choices=USER_TYPE_CHOICES, default='customer')
    phone = models.CharField(max_length=20, blank=True)
    company_name = models.CharField(max_length=100, blank=True)
    is_verified = models.BooleanField(default=False)
    auth_provider = models.CharField(max_length=20, default='email')
    email_verification_token = models.CharField(max_length=100, blank=True, null=True)

    # New optional profile_picture field
    profile_picture = models.URLField(blank=True, null=True)

    # Fix for reverse accessor clashes
    groups = models.ManyToManyField(
        'auth.Group',
        verbose_name='groups',
        blank=True,
        help_text='The groups this user belongs to.',
        related_name="customuser_set",
        related_query_name="user",
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        verbose_name='user permissions',
        blank=True,
        help_text='Specific permissions for this user.',
        related_name="customuser_set",
        related_query_name="user",
    )

    def __str__(self):
        return f"{self.username} ({self.user_type})"

    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"

# ========== Multi-Tenancy & Store Management ==========
class Store(models.Model):
    owner = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='stores')
    name = models.CharField(max_length=100)
    domain = models.CharField(max_length=100, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name_plural = "Stores"

# ========== Storefront Builder ==========
class StorefrontTemplate(models.Model):
    name = models.CharField(max_length=50)
    thumbnail = models.ImageField(upload_to='templates/')
    html_content = models.TextField()
    css_content = models.TextField()
    is_premium = models.BooleanField(default=False)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = "Template"
        verbose_name_plural = "Templates"

class Storefront(models.Model):
    store = models.OneToOneField(Store, on_delete=models.CASCADE, related_name='storefront')
    template = models.ForeignKey(StorefrontTemplate, on_delete=models.SET_NULL, null=True)
    custom_css = models.TextField(blank=True)
    sections_config = models.JSONField(default=dict)

    def __str__(self):
        return f"Storefront for {self.store.name}"

# ========== Product Management ==========
class Category(models.Model):
    store = models.ForeignKey(Store, on_delete=models.CASCADE, related_name='categories')
    name = models.CharField(max_length=50)
    parent = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name_plural = "Categories"

class Product(models.Model):
    store = models.ForeignKey(Store, on_delete=models.CASCADE, related_name='products')
    name = models.CharField(max_length=100)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    categories = models.ManyToManyField(Category)
    sku = models.CharField(max_length=50, unique=True)
    inventory = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    class Meta:
        ordering = ['-created_at']

# ========== Order Management ==========
class Order(models.Model):
    ORDER_STATUS = (
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('shipped', 'Shipped'),
        ('delivered', 'Delivered'),
        ('canceled', 'Canceled'),
    )
    
    store = models.ForeignKey(Store, on_delete=models.CASCADE, related_name='orders')
    customer = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True)
    total = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=20, choices=ORDER_STATUS, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Order #{self.id} - {self.status}"

    class Meta:
        ordering = ['-created_at']

class OrderItem(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='items')
    product = models.ForeignKey(Product, on_delete=models.PROTECT)
    quantity = models.PositiveIntegerField()
    price = models.DecimalField(max_digits=10, decimal_places=2)

    def __str__(self):
        return f"{self.quantity}x {self.product.name}"

    class Meta:
        verbose_name = "Order Item"
        verbose_name_plural = "Order Items"

class ReturnRequest(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE)
    reason = models.TextField()
    status = models.CharField(max_length=20, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Return for Order #{self.order.id}"

    class Meta:
        verbose_name = "Return Request"
        verbose_name_plural = "Return Requests"

# ========== Payment Integration ==========
class PaymentGateway(models.Model):
    GATEWAY_TYPES = (
        ('stripe', 'Stripe'),
        ('paypal', 'PayPal'),
        ('manual', 'Manual'),
    )
    
    store = models.ForeignKey(Store, on_delete=models.CASCADE, related_name='payment_gateways')
    gateway_type = models.CharField(max_length=20, choices=GATEWAY_TYPES)
    is_active = models.BooleanField(default=True)
    credentials = encrypt(models.JSONField())

    def __str__(self):
        return f"{self.get_gateway_type_display()} for {self.store.name}"

    class Meta:
        verbose_name = "Payment Gateway"
        verbose_name_plural = "Payment Gateways"

class Transaction(models.Model):
    order = models.OneToOneField(Order, on_delete=models.PROTECT)
    gateway = models.ForeignKey(PaymentGateway, on_delete=models.PROTECT)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=20)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Transaction #{self.id} - {self.status}"

# ========== Analytics ==========
class AnalyticsData(models.Model):
    store = models.ForeignKey(Store, on_delete=models.CASCADE, related_name='analytics')
    metric = models.CharField(max_length=50)
    value = models.JSONField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.metric} for {self.store.name}"

    class Meta:
        verbose_name = "Analytics Data"
        verbose_name_plural = "Analytics Data"
        ordering = ['-timestamp']

# ========== Third-Party Integrations ==========
class Integration(models.Model):
    SERVICE_TYPES = (
        ('seo', 'SEO Tools'),
        ('email', 'Email Marketing'),
        ('social', 'Social Media'),
    )
    
    store = models.ForeignKey(Store, on_delete=models.CASCADE, related_name='integrations')
    service_type = models.CharField(max_length=20, choices=SERVICE_TYPES)
    credentials = encrypt(models.JSONField())
    config = models.JSONField(default=dict)

    def __str__(self):
        return f"{self.get_service_type_display()} for {self.store.name}"

    class Meta:
        verbose_name = "Integration"
        verbose_name_plural = "Integrations"