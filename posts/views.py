from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import get_object_or_404
from django.db import IntegrityError
import json
from rest_framework.views import APIView  # Correct import (already correct)
from rest_framework.response import Response
from rest_framework import status
from rest_framework.generics import RetrieveAPIView
from django.contrib.auth.models import User
from .models import Post, Comment, Like, Follow, Dislike
from .serializers import UserSerializer, PostSerializer, CommentSerializer, LikeSerializer, DislikeSerializer
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated, AllowAny
from .permissions import IsPostAuthor
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
class UserListCreate(APIView):  # Fixed: ApiView -> APIView
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

class PostListCreate(APIView):  # Fixed: ApiView -> APIView
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
                author=request.user
            )
            serializer = PostSerializer(post)
            return Response({'message': 'Post created successfully!', 'post_id': post.id}, status=status.HTTP_201_CREATED)
        except ValueError as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': 'Failed to create post.', 'details': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class CommentListCreate(APIView):  # Fixed: ApiView -> APIView
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
class LikePostView(APIView):  # Fixed: ApiView -> APIView
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, post_id):
        logger = LoggerSingleton().get_logger()
        try:
            post = get_object_or_404(Post, id=post_id)
        except Http404:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)

        try:
            like, created = Like.objects.get_or_create(user=request.user, post=post)
            if not created:
                return Response({'error': 'You have already liked this post.'}, status=status.HTTP_400_BAD_REQUEST)
            logger.info(f"User {request.user.username} liked Post {post.id}")
            return Response({'message': 'Post liked successfully!'}, status=status.HTTP_201_CREATED)
        except Exception as e:
            logger.error(f"Failed to like post: {str(e)}")
            return Response({'error': 'Failed to like post.', 'details': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DislikePostView(APIView):  # Fixed: ApiView -> APIView
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, post_id):
        logger = LoggerSingleton().get_logger()
        try:
            post = get_object_or_404(Post, id=post_id)
        except Http404:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)

        try:
            # Optional: Prevent liking and disliking the same post
            if Like.objects.filter(user=request.user, post=post).exists():
                return Response({'error': 'You have already liked this post. Cannot dislike.'}, status=status.HTTP_400_BAD_REQUEST)
            
            dislike, created = Dislike.objects.get_or_create(user=request.user, post=post)
            if not created:
                return Response({'error': 'You have already disliked this post.'}, status=status.HTTP_400_BAD_REQUEST)
            logger.info(f"User {request.user.username} disliked Post {post.id}")
            return Response({'message': 'Post disliked successfully!'}, status=status.HTTP_201_CREATED)
        except Exception as e:
            logger.error(f"Failed to dislike post: {str(e)}")
            return Response({'error': 'Failed to dislike post.', 'details': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class CommentPostView(APIView):  # Fixed: ApiView -> APIView
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, post_id):
        logger = LoggerSingleton().get_logger()
        try:
            post = get_object_or_404(Post, id=post_id)
        except Http404:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)

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

class CommentListView(APIView):  # Fixed: ApiView -> APIView
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

# Retrieve a Single Post with Comments (GET)
class PostDetailView(APIView):  # Fixed: ApiView -> APIView
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated, IsPostAuthor]

    def get(self, request, pk):
        try:
            post = Post.objects.get(pk=pk)
            self.check_object_permissions(request, post)
            serializer = PostSerializer(post)
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
                'dislikes': DislikeSerializer(post.dislikes.all(), many=True).data
            })
        except Post.DoesNotExist:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# User Login View (Updated for Google OAuth compatibility)
class UserLoginView(APIView):  # Fixed: ApiView -> APIView
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
            # Check if user exists via Google OAuth (e.g., by email)
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
class GoogleLoginView(APIView):  # Fixed: ApiView -> APIView
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

            # Get the Google provider
            provider = GoogleProvider(request)
            app = provider.get_app(request)

            # Initialize OAuth2Client with correct parameters
            client = OAuth2Client(
                request=request,
                consumer_key=app.client_id,
                consumer_secret=app.secret,
                access_token_method='POST',
                access_token_url='https://oauth2.googleapis.com/token',
                callback_url='http://127.0.0.1:8000/accounts/google/login/callback/',
                scope=['profile', 'email'],
            )

            # Exchange the authorization code for an access token
            token = client.get_access_token(code)
            if not token:
                return Response({'error': 'Failed to exchange authorization code for token.'}, status=status.HTTP_400_BAD_REQUEST)

            # Get user data from Google using the adapter
            adapter = GoogleOAuth2Adapter(request)
            user_data = adapter.complete_login(request, app, token)
            if not user_data or 'email' not in user_data.account.extra_data:
                return Response({'error': 'Invalid user data from Google.'}, status=status.HTTP_400_BAD_REQUEST)

            email = user_data.account.extra_data['email']
            name = user_data.account.extra_data.get('name', email.split('@')[0])

            # Check if user exists
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                # Create new user if it doesn't exist
                user = User.objects.create_user(
                    username=name,
                    email=email,
                    password=None  # No password needed for Google OAuth
                )

            # Link or update Google account
            social_account, created = SocialAccount.objects.get_or_create(
                user=user,
                provider='google',
                uid=user_data.account.uid
            )
            social_account.extra_data = user_data.account.extra_data
            social_account.save()

            # Log the user in and generate or retrieve DRF token
            login(request, user)
            token, created = Token.objects.get_or_create(user=user)

            # Fetch profile picture (optional, if using Cloudinary or storing URLs)
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

class ProtectedView(APIView):  # Fixed: ApiView -> APIView
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"message": "Authenticated!"})

# FeedView (rolled back to pre-Homework 8 version, fixed typo)
class FeedView(APIView):  # Fixed: ApiView -> APIView
    """
    Retrieve a paginated feed of posts sorted by creation date (newest first).
    Supports filtering by 'followed' users or 'liked' posts.
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    pagination_class = PageNumberPagination

    def __init__(self):
        super().__init__()
        self.pagination_class.page_size = 10  # Default number of posts per page
        self.pagination_class.page_size_query_param = 'size'  # Allow client to specify size
        self.pagination_class.max_page_size = 50  # Maximum allowed size

    def get(self, request, *args, **kwargs):
        try:
            # Get pagination parameters for validation
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

            # Base query: Get posts sorted by date (newest first)
            posts = Post.objects.all().order_by('-created_at')

            # Apply filtering based on query parameter
            filter_type = request.query_params.get('filter', 'all')  # Default to 'all'
            followed_users = [request.user.id]  # Include user's own posts
            if hasattr(request.user, 'following'):
                followed_users.extend(request.user.following.values_list('followed__id', flat=True))

            if filter_type == 'followed':
                # Show only posts from followed users (and self)
                posts = posts.filter(author_id__in=followed_users)
            elif filter_type == 'liked':
                # Show only posts liked by the authenticated user
                liked_post_ids = request.user.likes.values_list('post_id', flat=True)
                posts = posts.filter(id__in=liked_post_ids)
            else:
                # Default: Show posts from followed users and self
                posts = posts.filter(author_id__in=followed_users)

            # Paginate the results
            paginator = self.pagination_class()
            paginated_posts = paginator.paginate_queryset(posts, request)
            serializer = PostSerializer(paginated_posts, many=True)
            return paginator.get_paginated_response(serializer.data)

        except Exception as e:
            logger.error(f"Error in FeedView: {str(e)}")
            return Response({"error": "Failed to retrieve feed.", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)