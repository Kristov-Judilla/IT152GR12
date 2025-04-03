from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import get_object_or_404
from django.db import IntegrityError
from django.core.cache import cache
import json
from rest_framework.views import APIView
from rest_framework.generics import GenericAPIView  # Only GenericAPIView from generics
from rest_framework.mixins import RetrieveModelMixin, DestroyModelMixin, UpdateModelMixin  # Correct module for mixins
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated, AllowAny
from .permissions import IsPostAuthor, RoleBasedPermission
from .models import Post, Comment, Like, Follow, Dislike
from .serializers import UserSerializer, PostSerializer, CommentSerializer, LikeSerializer, DislikeSerializer
from django.contrib.auth import authenticate, get_user_model, login
from rest_framework.authtoken.models import Token
from singletons.logger_singleton import LoggerSingleton
from factories.post_factory import PostFactory
from rest_framework.renderers import JSONRenderer
from django.http import Http404
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from allauth.socialaccount.models import SocialAccount
from allauth.socialaccount.providers.google.provider import GoogleProvider
from rest_framework.pagination import PageNumberPagination
from posts.permissions import AllowGuestsForPublicContent
from posts.models import Post
from posts.serializers import PostSerializer
import logging

logger = logging.getLogger(__name__)


# Get custom User model
User = get_user_model()
logger = LoggerSingleton().get_logger()

# Basic Hello World View
def hello_world_view(request):
    return HttpResponse("Hello, World! This is a basic Django view over HTTP.")

# Home view for the posts app
def posts_home(request):
    logger.info("Accessing posts_home view.")
    return HttpResponse("Welcome to the Posts API")

# Home view for Google API
def homepage_view(request):
    return HttpResponse("Welcome to the Homepage!")

# Retrieve All Users (GET)
@csrf_exempt
def get_users(request):
    try:
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return JsonResponse(serializer.data, safe=False)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

# Create a User (POST)
@csrf_exempt
def create_user(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            user = User.objects.create_user(
                username=data['username'],
                email=data['email'],
                password=data.get('password')
            )
            return JsonResponse({'id': user.id, 'message': 'User created successfully'}, status=201)
        except IntegrityError as e:
            if 'UNIQUE constraint' in str(e):
                return JsonResponse({'error': 'A user with this username or email already exists.'}, status=400)
            return JsonResponse({'error': str(e)}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)

# Retrieve All Posts (GET)
@csrf_exempt
def get_posts(request):
    try:
        posts = Post.objects.all()
        serializer = PostSerializer(posts, many=True)
        return JsonResponse(serializer.data, safe=False)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

# Create a Post (POST)
@csrf_exempt
def create_post(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            author = User.objects.get(id=data['author'])
            post = Post.objects.create(content=data['content'], author=author)
            return JsonResponse({'id': post.id, 'message': 'Post created successfully'}, status=201)
        except User.DoesNotExist:
            return JsonResponse({'error': 'Author not found'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)

# Delete a User (DELETE)
@csrf_exempt
def delete_user(request, user_id):
    if request.method == 'DELETE':
        try:
            user = User.objects.get(id=user_id)
            user.delete()
            return JsonResponse({'message': 'User deleted successfully'}, status=200)
        except User.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)

# Update a User (PUT)
@csrf_exempt
def update_user(request, id):
    if request.method == 'PUT':
        try:
            data = json.loads(request.body)
            user = get_object_or_404(User, id=id)
            user.username = data.get('username', user.username)
            user.email = data.get('email', user.email)
            user.save()
            return JsonResponse({'message': 'User updated successfully'}, status=200)
        except IntegrityError as e:
            if 'UNIQUE constraint' in str(e):
                return JsonResponse({'error': 'A user with this email already exists.'}, status=400)
            return JsonResponse({'error': str(e)}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)

# Class-based views for API
class UserListCreate(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PostListCreate(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        posts = Post.objects.all()
        serializer = PostSerializer(posts, many=True)
        return Response(serializer.data)

    def post(self, request):
        data = request.data
        try:
            post = PostFactory.create_post(
                post_type=data.get('post_type', 'text'),
                title=data['title'],
                content=data.get('content', ''),
                metadata=data.get('metadata', {}),
                author=request.user,
                privacy=data.get('privacy', 'public')  # Add privacy field
            )
            serializer = PostSerializer(post)
            return Response({'message': 'Post created successfully!', 'post_id': post.id}, status=status.HTTP_201_CREATED)
        except ValueError as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': 'Failed to create post.', 'details': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class CommentListCreate(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        comments = Comment.objects.all()
        serializer = CommentSerializer(comments, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = CommentSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Views for likes, dislikes, and comments (Homework 5)
class LikePostView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, post_id):
        logger = LoggerSingleton().get_logger()
        try:
            post = get_object_or_404(Post, id=post_id)
        except Http404:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)

        try:
            # Check if the user has already disliked the post; if so, remove the dislike
            existing_dislike = Dislike.objects.filter(user=request.user, post=post)
            if existing_dislike.exists():
                existing_dislike.delete()
                logger.info(f"Removed existing dislike by {request.user.username} on Post {post.id} before liking")

            like, created = Like.objects.get_or_create(user=request.user, post=post)
            if not created:
                return Response({'error': 'You have already liked this post.'}, status=status.HTTP_400_BAD_REQUEST)
            logger.info(f"User {request.user.username} liked Post {post.id}")
            return Response({'message': 'Post liked successfully!'}, status=status.HTTP_201_CREATED)
        except Exception as e:
            logger.error(f"Failed to like post: {str(e)}")
            return Response({'error': 'Failed to like post.', 'details': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DislikePostView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, post_id):
        logger = LoggerSingleton().get_logger()
        try:
            post = get_object_or_404(Post, id=post_id)
        except Http404:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)

        try:
            # Check if the user has already liked the post; if so, remove the like
            existing_like = Like.objects.filter(user=request.user, post=post)
            if existing_like.exists():
                existing_like.delete()
                logger.info(f"Removed existing like by {request.user.username} on Post {post.id} before disliking")

            dislike, created = Dislike.objects.get_or_create(user=request.user, post=post)
            if not created:
                return Response({'error': 'You have already disliked this post.'}, status=status.HTTP_400_BAD_REQUEST)
            logger.info(f"User {request.user.username} disliked Post {post.id}")
            return Response({'message': 'Post disliked successfully!'}, status=status.HTTP_201_CREATED)
        except Exception as e:
            logger.error(f"Failed to dislike post: {str(e)}")
            return Response({'error': 'Failed to dislike post.', 'details': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class CommentPostView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, post_id):
        logger = LoggerSingleton().get_logger()
        try:
            post = get_object_or_404(Post, id=post_id)
        except Http404:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)

        # Check privacy settings
        user = request.user
        user_role = getattr(user, 'role', None)
        is_admin = user_role == 'admin' if user_role else False

        if post.privacy == 'private' and not (is_admin or post.author == user):
            return Response({'detail': 'This post is private.'}, status=status.HTTP_403_FORBIDDEN)
        if post.privacy == 'friends_only':
            if not is_admin and post.author != user:
                following = user.following.filter(followed=post.author).exists() if user.is_authenticated else False
                if not following:
                    return Response({'detail': 'This post is only visible to friends.'}, status=status.HTTP_403_FORBIDDEN)

        serializer = CommentSerializer(data=request.data)
        if serializer.is_valid():
            try:
                serializer.save(author=request.user, post=post)
                logger.info(f"User {request.user.username} commented on Post {post.id}")
                return Response({'message': 'Comment added successfully!'}, status=status.HTTP_201_CREATED)
            except Exception as e:
                logger.error(f"Failed to add comment: {str(e)}")
                return Response({'error': 'Failed to add comment.', 'details': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class CommentListView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, post_id):
        try:
            post = get_object_or_404(Post, id=post_id)
        except Http404:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)

        comments = Comment.objects.filter(post=post).order_by('-created_at')
        serializer = CommentSerializer(comments, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

# Retrieve a Single Post with Comments (GET) and Delete (DELETE)
class PostDetailView(GenericAPIView, RetrieveModelMixin, DestroyModelMixin, UpdateModelMixin):
    authentication_classes = [TokenAuthentication]
    permission_classes = [RoleBasedPermission]
    queryset = Post.objects.all()
    serializer_class = PostSerializer
    lookup_field = 'pk'

    def get(self, request, *args, **kwargs):
        logger.info(f"GET request for post {kwargs.get('pk')} by {request.user.username}")
        instance = self.get_object()

        # Privacy check (already present, just confirming)
        user = request.user
        post = instance
        user_role = getattr(user, 'role', None)
        is_admin = user_role == 'admin' if user_role else False

        if post.privacy == 'private' and not (is_admin or post.author == user):
            return Response({'detail': 'This post is private.'}, status=status.HTTP_403_FORBIDDEN)
        if post.privacy == 'friends_only':
            if not is_admin and post.author != user:
                following = user.following.filter(followed=post.author).exists() if user.is_authenticated else False
                if not following:
                    return Response({'detail': 'This post is only visible to friends.'}, status=status.HTTP_403_FORBIDDEN)

        serializer = self.get_serializer(instance)
        return Response({
            'id': post.id,
            'title': post.title,
            'content': post.content,
            'author': UserSerializer(post.author).data,
            'post_type': post.post_type,
            'metadata': post.metadata,
            'created_at': post.created_at,
            'like_count': post.likes.count(),
            'dislike_count': post.dislikes.count(),
            'comment_count': post.comments.count(),
            'comments': CommentSerializer(post.comments.all(), many=True).data,
            'likes': LikeSerializer(post.likes.all(), many=True).data,
            'dislikes': DislikeSerializer(post.dislikes.all(), many=True).data,
            'privacy': post.privacy
        })

    def put(self, request, *args, **kwargs):
        logger.info(f"PUT request for post {kwargs.get('pk')} by {request.user.username}")
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=False)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response({
            'message': 'Post updated successfully',
            'post': serializer.data
        }, status=status.HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        logger.info(f"DELETE request for post {kwargs.get('pk')} by {request.user.username}")
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response({'message': 'Post deleted successfully'}, status=status.HTTP_200_OK)

# User Login View (Updated for Google OAuth compatibility)
class UserLoginView(APIView):
    permission_classes = [AllowAny]
    renderer_classes = [JSONRenderer]

    def post(self, request):
        logger = LoggerSingleton().get_logger()
        username = request.data.get('username')
        password = request.data.get('password')
        logger.info(f"Login attempt for user: {username}")
        user = authenticate(request, username=username, password=password)
        if user is not None:
            token, created = Token.objects.get_or_create(user=user)
            logger.info(f"User {username} logged in successfully")
            return Response({'token': token.key}, status=status.HTTP_200_OK)
        else:
            email = request.data.get('email')
            if email:
                try:
                    user = User.objects.get(email=email)
                    token, created = Token.objects.get_or_create(user=user)
                    logger.info(f"User {email} logged in via email match")
                    return Response({'token': token.key}, status=status.HTTP_200_OK)
                except User.DoesNotExist:
                    pass
        logger.error(f"Failed login attempt for user: {username or email}")
        return Response({'error': 'Invalid Credentials'}, status=status.HTTP_401_UNAUTHORIZED)

# Google OAuth Login View (Updated and corrected for django-allauth)
class GoogleLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        try:
            code = request.data.get('code')
            if not code:
                return Response({'error': 'Authorization code is required.'}, status=status.HTTP_400_BAD_REQUEST)

            from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
            from allauth.socialaccount.providers.oauth2.client import OAuth2Client
            from allauth.socialaccount.models import SocialAccount
            from allauth.socialaccount.providers.google.provider import GoogleProvider
            from django.contrib.auth import login

            provider = GoogleProvider(request)
            app = provider.get_app(request)

            client = OAuth2Client(
                request=request,
                consumer_key=app.client_id,
                consumer_secret=app.secret,
                access_token_method='POST',
                access_token_url='https://oauth2.googleapis.com/token',
                callback_url='http://127.0.0.1:8000/accounts/google/login/callback/',
                scope=['profile', 'email'],
            )

            token = client.get_access_token(code)
            if not token:
                return Response({'error': 'Failed to exchange authorization code for token.'}, status=status.HTTP_400_BAD_REQUEST)

            adapter = GoogleOAuth2Adapter(request)
            user_data = adapter.complete_login(request, app, token)
            if not user_data or 'email' not in user_data.account.extra_data:
                return Response({'error': 'Invalid user data from Google.'}, status=status.HTTP_400_BAD_REQUEST)

            email = user_data.account.extra_data['email']
            name = user_data.account.extra_data.get('name', email.split('@')[0])

            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                user = User.objects.create_user(
                    username=name,
                    email=email,
                    password=None
                )

            social_account, created = SocialAccount.objects.get_or_create(
                user=user,
                provider='google',
                uid=user_data.account.uid
            )
            social_account.extra_data = user_data.account.extra_data
            social_account.save()

            login(request, user)
            token, created = Token.objects.get_or_create(user=user)

            profile_picture = user_data.account.extra_data.get('picture')
            if profile_picture:
                user.profile_picture = profile_picture  # Requires CloudinaryField in models.py
                user.save()

            logger.info(f"User {user.username} logged in via Google OAuth")
            return Response({
                'token': token.key,
                'user': UserSerializer(user).data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Google OAuth login failed: {str(e)}")
            return Response({'error': 'Google OAuth login failed.', 'details': str(e)}, status=status.HTTP_400_BAD_REQUEST)

class ProtectedView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"message": "Authenticated!"})

# FeedView (rolled back to pre-Homework 8 version, fixed typo)
class FeedView(APIView):
    """
    Retrieve a paginated feed of posts sorted by creation date (newest first).
    Supports filtering by 'followed' users or 'liked' posts.
    Guests can only view public content.
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [AllowGuestsForPublicContent]
    pagination_class = PageNumberPagination

    def __init__(self):
        super().__init__()
        self.pagination_class.page_size = 10
        self.pagination_class.page_size_query_param = 'size'
        self.pagination_class.max_page_size = 50

    def get(self, request, *args, **kwargs):
        try:
            # Validate pagination parameters
            page = request.query_params.get('page', 1)
            size = request.query_params.get('size', 10)
            try:
                page = int(page)
                size = int(size)
                if size > self.pagination_class.max_page_size:
                    size = self.pagination_class.max_page_size
                if page < 1:
                    raise ValueError
            except (ValueError, TypeError):
                return Response({"error": "Invalid page or size parameter."}, status=status.HTTP_400_BAD_REQUEST)

            # Generate cache key
            user_id = request.user.id if request.user.is_authenticated else 'guest'
            cache_key = f"feed_{user_id}_page_{page}_size_{size}_filter_{request.query_params.get('filter', 'all')}"
            cached_data = cache.get(cache_key)

            if cached_data:
                logger.info(f"Cache hit for {cache_key}")
                return Response(cached_data)

            # Optimize query with select_related and prefetch_related
            posts = Post.objects.select_related('author').prefetch_related('likes', 'dislikes', 'comments').order_by('-created_at')

            # Apply privacy filtering
            if not request.user.is_authenticated:
                # Guests can only see public posts
                posts = posts.filter(privacy='public')
            else:
                user = request.user
                user_role = getattr(user, 'role', None)
                is_admin = user_role == 'admin' if user_role else False

                # Define followed_users for all authenticated users
                followed_users = [user.id]
                if hasattr(user, 'following'):
                    followed_users.extend(user.following.values_list('followed__id', flat=True))

                if is_admin:
                    # Admins see all posts
                    filtered_posts = posts
                else:
                    # Authenticated users see public, their own private, and friends_only from followed users
                    filtered_posts = posts.filter(
                        models.Q(privacy='public') |
                        (models.Q(privacy='private') & models.Q(author=user)) |
                        (models.Q(privacy='friends_only') & models.Q(author__id__in=followed_users))
                    )

                # Apply additional filtering (followed or liked)
                filter_type = request.query_params.get('filter', 'all')
                if filter_type == 'followed':
                    filtered_posts = filtered_posts.filter(author_id__in=followed_users)
                elif filter_type == 'liked':
                    liked_post_ids = user.likes.values_list('post_id', flat=True)
                    filtered_posts = filtered_posts.filter(id__in=liked_post_ids)
                else:
                    filtered_posts = filtered_posts.filter(author_id__in=followed_users)

                posts = filtered_posts

            # Apply pagination
            paginator = self.pagination_class()
            paginated_posts = paginator.paginate_queryset(posts, request)
            serializer = PostSerializer(paginated_posts, many=True)

            # Cache the paginated response
            response_data = paginator.get_paginated_response(serializer.data).data
            cache.set(cache_key, response_data, timeout=300)  # Cache for 5 minutes
            logger.info(f"Cache set for {cache_key}")

            return Response(response_data)

        except Exception as e:
            logger.error(f"Error in FeedView: {str(e)}")
            return Response({"error": "Failed to retrieve feed.", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)