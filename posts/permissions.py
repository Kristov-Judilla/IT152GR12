# posts/permissions.py
from rest_framework.permissions import BasePermission
from .models import User, Post, Comment
import logging

logger = logging.getLogger(__name__)

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
        # Allow admins or the post author to perform other actions (e.g., DELETE, PUT, PATCH)
        return request.user.is_authenticated and (
            request.user.role == 'admin' or obj.author == request.user
        )

class RoleBasedPermission(BasePermission):
    """
    Custom permission to enforce role-based access control (RBAC) with view-specific rules.
    - Admins can delete or edit any post.
    - Post authors can delete or edit their own posts.
    - Admins, moderators, or comment authors can delete comments.
    - All authenticated users can comment.
    - Only admins can create users.
    - Debug logging added for troubleshooting.
    """
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        
        # Define role-based permissions
        if request.method in ['DELETE', 'PUT', 'PATCH'] and hasattr(view, 'queryset') and view.queryset.model == Post:
            user_role = getattr(request.user, 'role', None)
            is_admin = user_role == 'admin' if user_role else False
            logger.info(f"RoleBasedPermission: Checking {request.method} for user {request.user.username}, role={user_role}, is_admin={is_admin}")
            return True  # Allow all authenticated users to proceed to object-level check
        if request.method == 'POST' and hasattr(view, 'queryset') and view.queryset.model == User:
            user_role = getattr(request.user, 'role', None)
            is_admin = user_role == 'admin' if user_role else False
            logger.info(f"RoleBasedPermission: Checking POST for user creation by {request.user.username}, role={user_role}, is_admin={is_admin}")
            return is_admin  # Only admins can create users
        if view.__class__.__name__ == 'CommentPostView' and request.method in ['POST']:
            return request.user.role in ['admin', 'moderator', 'user']  # All roles can comment
        return True  # Default allow for other actions

    def has_object_permission(self, request, view, obj):
        if not request.user.is_authenticated:
            return False
        
        user_role = getattr(request.user, 'role', None)
        is_admin = user_role == 'admin' if user_role else False
        is_moderator = user_role == 'moderator' if user_role else False

        if isinstance(obj, Post) and request.method in ['DELETE', 'PUT', 'PATCH']:
            logger.info(f"RoleBasedPermission: Object check for {request.method}, user {request.user.username}, role={user_role}, is_admin={is_admin}, is_author={obj.author == request.user}")
            return is_admin or obj.author == request.user  # Admins or author can delete/edit posts
        if isinstance(obj, Comment) and request.method in ['DELETE']:
            logger.info(f"RoleBasedPermission: Object check for DELETE, user {request.user.username}, role={user_role}, is_moderator={is_moderator}, is_author={obj.author == request.user}")
            return is_admin or is_moderator or obj.author == request.user  # Admins, moderators, or author can delete comments
        return True
    from rest_framework.permissions import BasePermission

class AllowGuestsForPublicContent(BasePermission):
    def has_permission(self, request, view):
        # Allow all users (authenticated or not) to access the endpoint
        return True

    def has_object_permission(self, request, view, obj):
        # For object-level permissions (e.g., PostDetailView), ensure guests can only access public content
        if not request.user.is_authenticated:
            return obj.privacy == 'public'
        return True  # Authenticated users will have their access checked in the view