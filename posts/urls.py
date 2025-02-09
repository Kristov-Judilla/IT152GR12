from django.urls import path
from . import views
from .views import UserListCreate, PostListCreate, CommentListCreate

urlpatterns = [
    # Function-based view URLs
    path('users/', views.get_users, name='get_users'),
    path('users/create/', views.create_user, name='create_user'),
    path('users/<int:user_id>/', views.delete_user, name='delete_user'),
    path('users/update/<int:id>/', views.update_user, name='update_user'),
    path('posts/', views.get_posts, name='get_posts'),
    path('posts/create/', views.create_post, name='create_post'),

    # Class-based view URLs
    path('api/users/', UserListCreate.as_view(), name='user-list-create'),
    path('api/posts/', PostListCreate.as_view(), name='post-list-create'),
    path('api/comments/', CommentListCreate.as_view(), name='comment-list-create'),
]