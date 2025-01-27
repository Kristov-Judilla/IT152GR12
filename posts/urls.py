from django.urls import path
from . import views

urlpatterns = [
    path('users/', views.get_users, name='get_users'),
    path('users/create/', views.create_user, name='create_user'),
    path('users/<int:user_id>/', views.delete_user, name='delete_user'),  # Add this line
    path('users/update/<int:id>/', views.update_user, name='update_user'),  # UPDATE user
    path('posts/', views.get_posts, name='get_posts'),
    path('posts/create/', views.create_post, name='create_post'),
]