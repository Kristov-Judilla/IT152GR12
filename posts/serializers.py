from rest_framework import serializers
from .models import User, Post, Comment, Like, Dislike  # Added Dislike
from django.contrib.auth import get_user_model

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'created_at']

class CommentSerializer(serializers.ModelSerializer):
    author = UserSerializer(read_only=True)
    post = serializers.PrimaryKeyRelatedField(read_only=True)  # Make post read-only

    class Meta:
        model = Comment
        fields = ['id', 'text', 'author', 'post', 'created_at']

    def validate_text(self, value):
        if not value.strip():
            raise serializers.ValidationError("Comment text cannot be empty.")
        return value

class LikeSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = Like
        fields = ['id', 'user', 'post', 'created_at']

class DislikeSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)  # Added for consistency with LikeSerializer

    class Meta:
        model = Dislike
        fields = ['id', 'user', 'post', 'created_at']

class PostSerializer(serializers.ModelSerializer):
    """
    Serializer for the Post model, handling post data.
    """
    author = UserSerializer(read_only=True)
    post_type = serializers.CharField(default='text', read_only=True)
    metadata = serializers.ListField(default=[], read_only=True)
    # Explicitly define the privacy field to override default choices validation
    privacy = serializers.CharField(max_length=20)

    class Meta:
        model = Post
        fields = ['id', 'title', 'content', 'privacy', 'author', 'post_type', 'metadata', 'created_at', 'likes', 'dislikes', 'comments']
        read_only_fields = ['author', 'post_type', 'metadata', 'created_at', 'likes', 'dislikes', 'comments']

    def validate_privacy(self, value):
        """
        Validate that the privacy value is one of the allowed choices.
        Normalize the value to lowercase to handle case-insensitive input.
        """
        value = value.lower()
        valid_choices = [choice[0] for choice in Post.PRIVACY_CHOICES]
        if value not in valid_choices:
            raise serializers.ValidationError("Privacy must be 'public' or 'private'.")
        return value


    def get_author(self, obj):
        # Return a simplified author representation
        return {
            'id': obj.author.id,
            'username': obj.author.username,
            'email': obj.author.email
        }
    