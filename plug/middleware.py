from django.utils.deprecation import MiddlewareMixin
from .models import Store

class TenantMiddleware(MiddlewareMixin):
    def process_request(self, request):
        host = request.get_host().split(':')[0]
        subdomain = host.split('.')[0]
        
        try:
            store = Store.objects.get(domain=subdomain)
            request.store = store
        except Store.DoesNotExist:
            request.store = None
