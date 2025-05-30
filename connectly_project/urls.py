"""
URL configuration for connectly_project project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from posts.views import GoogleLoginView  # Correct import
from posts.views import homepage_view, GoogleLoginView # ... other view imports ...

urlpatterns = [
    path('', homepage_view, name='homepage'),
    path('admin/', admin.site.urls),
    path('api-auth/', include('rest_framework.urls')),
    path('posts/', include('posts.urls')),  # **Keep this line - URLs will be like /posts/users/, /posts/posts/, etc.**
    path('accounts/', include('allauth.urls')),  # Add allauth URLs    
    path('auth/google/login/', GoogleLoginView.as_view(), name='google-login'),  # Use GoogleLoginView directly
    path('api/', include('posts.urls')),
    path('posts/', include('posts.urls')),  # Include posts app URLs
    
]