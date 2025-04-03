from django.contrib import admin
from .models import Post, Comment, Like, User, Dislike
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from rest_framework.authtoken.models import Token

# Custom admin class for Dislike to control display
@admin.register(Dislike)
class DislikeAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'post', 'created_at')  # Fields to display in the list view
    list_filter = ('created_at', 'user')  # Add filters for created_at and user
    search_fields = ('user__username', 'post__title')  # Enable search by username and post title
    ordering = ('-created_at',)  # Sort by creation date (newest first)

class UserAdmin(BaseUserAdmin):
    # Define fields to display in the admin form
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal info', {'fields': ('email', 'role')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )

    # Fields to display in the user list view
    list_display = ('username', 'email', 'role', 'is_staff')
    search_fields = ('username', 'email')
    ordering = ('username',)

    # Add actions to allow password changes
    actions = ['change_password']

    def change_password(self, request, queryset):
        # This is a placeholder; Django uses its built-in password change view
        from django.contrib.auth.views import PasswordChangeView
        return self.admin_site.admin_view(PasswordChangeView.as_view())(request)

# Register your models here
admin.site.register(Post)
admin.site.register(Comment)
admin.site.register(Like)
admin.site.register(User, UserAdmin)
admin.site.register(Token)  # Optional, if you want to manage tokens in admin