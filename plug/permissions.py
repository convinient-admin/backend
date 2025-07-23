from rest_framework import permissions

class StoreBasedPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.user.is_superuser:
            return True
        return request.user.user_type == 'merchant'

    def has_object_permission(self, request, view, obj):
        return obj.store.owner == request.user
