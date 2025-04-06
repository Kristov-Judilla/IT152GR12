from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import get_object_or_404
from django.db import IntegrityError
from django.db import models  # Added to fix the error
from django.core.cache import cache
import json
from rest_framework.views import APIView
from rest_framework.generics import GenericAPIView  # Only GenericAPIView from generics
from rest_framework.mixins import RetrieveModelMixin, DestroyModelMixin, UpdateModelMixin  # Correct module for mixins
from rest_framework.permissions import IsAdminUser, AllowAny  # Import for admin-only access
from posts.permissions import AllowGuestsForPublicContent  # Custom permission
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
from posts.models import Post
from posts.serializers import PostSerializer
from rest_framework import status, permissions
import logging
import time

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
    
class AllowAuthenticatedCreate(permissions.BasePermission):
    """
    Custom permission to:
    - Allow any authenticated user to create a post (POST).
    - Restrict listing posts (GET) to admins only.
    """
    def has_permission(self, request, view):
        # Allow POST requests for any authenticated user
        if request.method == 'POST':
            return request.user and request.user.is_authenticated
        # Allow GET requests only for admins
        elif request.method == 'GET':
            user_role = getattr(request.user, 'role', None)
            is_admin = user_role == 'admin' if user_role else False
            return is_admin
        return False

# Class-based views for API
class UserListCreate(APIView):
    """
    API view to create new users with specified roles (e.g., admin, user).
    - Admins can create users with any role.
    - Regular users can self-register with the "user" role.
    Endpoint: POST /posts/api/users/
    """
    authentication_classes = [TokenAuthentication]

    def get_permissions(self):
        """
        Dynamically set permissions based on the request.
        - AllowAny for self-registration (role="user" by authenticated users).
        - IsAdminUser for creating users with any role.
        Returns:
            List of permission classes.
        """
        if self.request.user.is_authenticated and self.request.data.get("role") == "user":
            return [AllowAny()]  # Allow authenticated users to self-register as "user"
        return [IsAdminUser()]  # Restrict other creations to admins
    
    def get(self, request, *args, **kwargs):
        """
        Handle GET requests to list all registered users.
        Args:
            request: The HTTP request object.
        Returns:
            Response: A list of all users in JSON format.
        """
        try:
            users = User.objects.all()
            serializer = UserSerializer(users, many=True)
            logger.info(f"Admin {request.user.username} listed all users")
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error listing users: {str(e)}")
            return Response(
                {"error": "Failed to list users.", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def post(self, request, *args, **kwargs):
        """
        Handle POST requests to create a new user.
        Args:
            request: The HTTP request object containing user data (username, email, password, role).
        Returns:
            Response: The created user data with a 201 status, or an error with 400/500 status.
        """
        try:
            # Step 1: Extract data from the request
            data = request.data
            username = data.get("username")
            email = data.get("email")
            password = data.get("password")
            role = data.get("role", "user")  # Default to "user" if not provided

            # Step 2: Validate required fields
            if not all([username, email, password]):
                logger.warning("Missing required fields in user creation request")
                return Response(
                    {"error": "Username, email, and password are required."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Step 3: Check permissions for role assignment
            if not request.user.is_authenticated:
                return Response(
                    {"error": "Authentication required to create a user."},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            if role == "admin" and not request.user.is_staff:  # Prevent non-admins from creating admins
                return Response(
                    {"error": "Only admins can create admin users."},
                    status=status.HTTP_403_FORBIDDEN
                )

            # Step 4: Prevent users from self-upgrading to admin
            if role == "admin" and request.user.username == username:
                return Response(
                    {"error": "Cannot self-register as admin."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Step 5: Create the user with the specified role
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                role=role
            )

            # Step 6: Serialize the user data for the response
            serializer = UserSerializer(user)
            logger.info(f"Created user {username} with role {role}")

            return Response(serializer.data, status=status.HTTP_201_CREATED)

        except Exception as e:
            # Log any errors and return a 500 response
            logger.error(f"Error creating user: {str(e)}")
            return Response(
                {"error": "Failed to create user.", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class PostListCreate(APIView):
    """
    API view for admins to create and list posts.
    - POST: Create a new post (restricted to admins).
    - GET: List all posts (restricted to admins for now; can be adjusted).
    Endpoint: /posts/api/posts/
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [AllowAuthenticatedCreate]  # Only admins can create or list posts

    def get(self, request, *args, **kwargs):
        """
        Handle GET requests to list all posts (admin-only for now).
        Args:
            request: The HTTP request object.
        Returns:
            Response: A list of all posts in JSON format.
        """
        try:
            posts = Post.objects.all()
            serializer = PostSerializer(posts, many=True)
            logger.info(f"Admin {request.user.username} listed all posts")
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error listing posts: {str(e)}")
            return Response(
                {"error": "Failed to list posts.", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def post(self, request, *args, **kwargs):
        """
        Handle POST requests to create a new post.
        Args:
            request: The HTTP request object containing post data (title, content, privacy).
        Returns:
            Response: The created post data with a 201 status, or an error with 400/500 status.
        """
        try:
            # Step 1: Extract data from the request
            data = request.data
            title = data.get("title")
            content = data.get("content")
            privacy = data.get("privacy", "public")  # Default to public if not provided

            # Step 2: Validate required fields
            if not all([title, content]):
                logger.warning("Missing required fields in post creation request")
                return Response(
                    {"error": "Title and content are required."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Step 3: Validate privacy value
            if privacy not in ['public', 'private', 'friends_only']:
                return Response(
                    {"error": "Privacy must be 'public', 'private', or 'friends_only'."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Step 4: Create the post with the authenticated user as author
            if not request.user.is_authenticated:
                return Response(
                    {"error": "Authentication required to create a post."},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            post = Post.objects.create(
                title=title,
                content=content,
                privacy=privacy,
                author=request.user
            )

            # Step 5: Serialize the post data for the response
            serializer = PostSerializer(post)
            logger.info(f"Admin {request.user.username} created post {title} with privacy {privacy}")

            # Step 6: Invalidate feed cache to reflect the new post
            cache.clear()  # Clears all cache entries
            logger.info("Cleared feed cache after creating new post")

            return Response(serializer.data, status=status.HTTP_201_CREATED)

        except Exception as e:
            logger.error(f"Error creating post: {str(e)}")
            return Response(
                {"error": "Failed to create post.", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

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

        # Log the updated privacy value for debugging
        updated_post = Post.objects.get(pk=instance.pk)
        logger.info(f"Updated post {instance.pk} privacy to {updated_post.privacy}")

        # Invalidate feed cache to reflect the update
        cache.clear()
        logger.info("Cleared feed cache after updating post")

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
    API view to retrieve a paginated feed of posts.
    Features:
    - GET: Guests can view only public posts; authenticated users see all public posts and their own private posts.
    - Implements caching to improve performance.
    - Uses query optimization with select_related and prefetch_related.
    Endpoint: /posts/feed/
    """
    authentication_classes = [TokenAuthentication]  # Optional for authenticated users
    permission_classes = [AllowGuestsForPublicContent]  # Allow guests for public content
    pagination_class = PageNumberPagination

    cache_hits = 0
    cache_misses = 0
    request_count = 0
    LOG_INTERVAL = 100

    def __init__(self):
        """Initialize pagination settings for the feed."""
        super().__init__()
        self.pagination_class.page_size = 10  # Default page size
        self.pagination_class.page_size_query_param = 'size'  # Allow size override via query param
        self.pagination_class.max_page_size = 50  # Maximum page size to prevent abuse

    def get(self, request, *args, **kwargs):
        """
        Handle GET requests to retrieve the feed.
        Args:
            request: The HTTP request object.
        Returns:
            Response: A paginated list of posts in JSON format.
        """
        # Measure start time
        start_time = time.time()

        try:
            # Increment request counter
            FeedView.request_count += 1

            # Step 1: Validate pagination parameters
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
                return Response(
                    {"error": "Invalid page or size parameter."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Step 2: Generate a unique cache key based on user and request parameters
            user_id = request.user.id if request.user.is_authenticated else 'guest'
            cache_key = f"feed_{user_id}_page_{page}_size_{size}_filter_{request.query_params.get('filter', 'all')}"
            cached_data = cache.get(cache_key)

            # Step 3: Track cache hits and misses
            if cached_data:
                FeedView.cache_hits += 1
                logger.info(f"Cache hit for {cache_key}")
                # Log response time for cache hit
                elapsed_time = (time.time() - start_time) * 1000  # Convert to milliseconds
                logger.info(f"Response time (cache hit): {elapsed_time:.2f} ms")
                return Response(cached_data)
            else:
                FeedView.cache_misses += 1
                logger.info(f"Cache miss for {cache_key}")

            # Log cache hit rate every LOG_INTERVAL requests
            if FeedView.request_count % FeedView.LOG_INTERVAL == 0:
                total_requests = FeedView.cache_hits + FeedView.cache_misses
                if total_requests > 0:
                    hit_rate = (FeedView.cache_hits / total_requests) * 100
                    logger.info(
                        f"Cache Hit Rate: {hit_rate:.2f}% "
                        f"(Hits: {FeedView.cache_hits}, Misses: {FeedView.cache_misses}, Total: {total_requests})"
                    )

            # Step 4: Query posts with optimization
            posts = Post.objects.select_related('author').prefetch_related(
                'likes', 'dislikes', 'comments'
            ).order_by('-created_at')

            # Step 5: Apply privacy and user-based filtering
            if not request.user.is_authenticated:
                # Guests can only see public posts
                posts = posts.filter(privacy='public')
            else:
                user = request.user
                user_role = getattr(user, 'role', None)
                is_admin = user_role == 'admin' if user_role else False

                if is_admin:
                    # Admins see all posts
                    filtered_posts = posts
                else:
                    # Non-admin users see:
                    # - All public posts
                    # - Their own private posts
                    filtered_posts = posts.filter(
                        models.Q(privacy='public') |
                        (models.Q(privacy='private') & models.Q(author=user))
                    )

                # Step 6: Apply additional filtering based on query parameters
                filter_type = request.query_params.get('filter', 'all')
                if filter_type == 'liked':
                    liked_post_ids = user.likes.values_list('post_id', flat=True)
                    filtered_posts = filtered_posts.filter(id__in=liked_post_ids)
                # Removed 'followed' filter since there's no follow functionality
                # Removed default author_id__in=followed_users filter to show all public posts

                posts = filtered_posts

            # Step 7: Apply pagination to the filtered posts
            paginator = self.pagination_class()
            paginated_posts = paginator.paginate_queryset(posts, request)
            serializer = PostSerializer(paginated_posts, many=True)

            # Step 8: Cache the response for future requests
            response_data = paginator.get_paginated_response(serializer.data).data
            cache.set(cache_key, response_data, timeout=300)  # Cache for 5 minutes
            logger.info(f"Cache set for {cache_key}")

            # Log response time for cache miss
            elapsed_time = (time.time() - start_time) * 1000  # Convert to milliseconds
            logger.info(f"Response time (cache miss): {elapsed_time:.2f} ms")

            return Response(response_data)

        except Exception as e:
            # Log any errors and return a 500 response
            logger.error(f"Error in FeedView: {str(e)}")
            return Response(
                {"error": "Failed to retrieve feed.", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
# API view for admins to retrieve, update, or delete a specific user.     
class UserDetail(APIView):
    """
    API view for admins to retrieve, update, or delete a specific user.
    - GET: Retrieve a user's details.
    - PUT: Update a user's details (e.g., change role).
    - DELETE: Delete a user.
    Endpoint: /posts/api/users/<id>/
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAdminUser]  # Only admins can access this view

    def get(self, request, pk, *args, **kwargs):
        """
        Handle GET requests to retrieve a specific user.
        Args:
            request: The HTTP request object.
            pk: The primary key (ID) of the user to retrieve.
        Returns:
            Response: The user's data in JSON format, or 404 if not found.
        """
        try:
            user = User.objects.get(pk=pk)
            serializer = UserSerializer(user)
            logger.info(f"Admin {request.user.username} retrieved user {user.username}")
            return Response(serializer.data, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            logger.warning(f"User with ID {pk} not found")
            return Response(
                {"error": "User not found."},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Error retrieving user: {str(e)}")
            return Response(
                {"error": "Failed to retrieve user.", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def put(self, request, pk, *args, **kwargs):
        """
        Handle PUT requests to update a specific user.
        Args:
            request: The HTTP request object containing updated user data.
            pk: The primary key (ID) of the user to update.
        Returns:
            Response: The updated user data, or 404/400 if invalid.
        """
        try:
            user = User.objects.get(pk=pk)
            data = request.data

            # Update fields if provided
            if "username" in data:
                user.username = data["username"]
            if "email" in data:
                user.email = data["email"]
            if "password" in data:
                user.set_password(data["password"])
            if "role" in data:
                user.role = data["role"]

            user.save()
            serializer = UserSerializer(user)
            logger.info(f"Admin {request.user.username} updated user {user.username}")
            return Response(serializer.data, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            logger.warning(f"User with ID {pk} not found")
            return Response(
                {"error": "User not found."},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Error updating user: {str(e)}")
            return Response(
                {"error": "Failed to update user.", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def delete(self, request, pk, *args, **kwargs):
        """
        Handle DELETE requests to delete a specific user.
        Args:
            request: The HTTP request object.
            pk: The primary key (ID) of the user to delete.
        Returns:
            Response: 204 on success, or 404 if not found.
        """
        try:
            user = User.objects.get(pk=pk)
            username = user.username
            user.delete()
            logger.info(f"Admin {request.user.username} deleted user {username}")
            return Response(status=status.HTTP_204_NO_CONTENT)

        except User.DoesNotExist:
            logger.warning(f"User with ID {pk} not found")
            return Response(
                {"error": "User not found."},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Error deleting user: {str(e)}")
            return Response(
                {"error": "Failed to delete user.", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )