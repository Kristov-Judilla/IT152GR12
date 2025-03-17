from django.contrib import admin
from .models import Post, Comment, Like, User, Dislike
from rest_framework.authtoken.models import Token

# Custom admin class for Dislike to control display
@admin.register(Dislike)
class DislikeAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'post', 'created_at')  # Fields to display in the list view
    list_filter = ('created_at', 'user')  # Add filters for created_at and user
    search_fields = ('user__username', 'post__title')  # Enable search by username and post title
    ordering = ('-created_at',)  # Sort by creation date (newest first)

# Register your models here
admin.site.register(Post)
admin.site.register(Comment)
admin.site.register(Like)
admin.site.register(User)  # Register the User model
admin.site.register(Token)  # Optional, if you want to manage tokens in admin