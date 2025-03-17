from django.contrib import admin
from .models import Post, Comment, Like, User
from rest_framework.authtoken.models import Token

# Register your models here
admin.site.register(Post)
admin.site.register(Comment)
admin.site.register(Like)
admin.site.register(User)  # Register the User model
admin.site.register(Token)  # Optional, if you want to manage tokens in admin