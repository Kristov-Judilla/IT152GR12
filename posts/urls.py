from django.urls import path
from . import views
from .views import UserListCreate, PostListCreate, CommentListCreate, LikePostView, CommentPostView, CommentListView, PostDetailView, FeedView

urlpatterns = [
    # Basic Hello World View at root path
    path('', views.hello_world_view, name='hello-world'),
    
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
    path('api/login/', views.UserLoginView.as_view(), name='api-login'),
    path('api/posts/<int:pk>/', PostDetailView.as_view(), name='post-detail'),

    # New endpoints for likes and comments (added from Homework 5)
    path('<int:post_id>/like/', LikePostView.as_view(), name='post-like'),
    path('<int:post_id>/comment/', CommentPostView.as_view(), name='post-comment'),
    path('<int:post_id>/comments/', CommentListView.as_view(), name='post-comments'),

    # New endpoint for Homework 7: News Feed
    path('feed/', FeedView.as_view(), name='feed'),
]