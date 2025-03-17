from rest_framework.permissions import BasePermission

class IsPostAuthor(BasePermission):
    """
    Custom permission to only allow authors of a post to access it.
    """
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any request,
        # so we'll always allow GET, HEAD or OPTIONS requests.
        if request.method in ['GET', 'HEAD', 'OPTIONS']: # or SAFE_METHODS if you want to use DRF's SAFE_METHODS
            return True

        # Write permissions are allowed to the author of the post.
        return obj.author == request.user