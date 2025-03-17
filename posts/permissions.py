from rest_framework.permissions import BasePermission
from .models import User

class IsPostAuthor(BasePermission):
    """
    Custom permission to only allow authors of a post to access it.
    """
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any request,
        # so we'll always allow GET, HEAD or OPTIONS requests.
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return True

        # Write permissions are allowed to the author of the post.
        return obj.author == request.user

class IsAdminOrPostAuthor(BasePermission):
    """
    Custom permission to allow only admins or post authors to perform actions.
    """
    def has_object_permission(self, request, view, obj):
        # Allow GET, HEAD, or OPTIONS requests for all authenticated users
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return request.user and request.user.is_authenticated
        # Allow admins or the post author to perform other actions (e.g., DELETE)
        return request.user.is_authenticated and (
            request.user.role == 'admin' or obj.author == request.user
        )