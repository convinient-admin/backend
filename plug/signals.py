from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from .models import OrderItem, Product

@receiver(post_save, sender=OrderItem)
def update_inventory(sender, instance, created, **kwargs):
    if created:
        product = instance.product
        product.inventory -= instance.quantity
        product.save()
