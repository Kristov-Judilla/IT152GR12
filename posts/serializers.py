from rest_framework import serializers
from .models import User, Post, Comment, Like, Dislike  # Added Dislike

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
    # Serialize the author as a nested object (using UserSerializer)
    author = serializers.SerializerMethodField()
    # Serialize likes and dislikes as lists of objects
    likes = LikeSerializer(many=True, read_only=True)
    dislikes = DislikeSerializer(many=True, read_only=True)  # Added dislikes
    # Optionally include comments for consistency with PostDetailView
    comments = CommentSerializer(many=True, read_only=True)

    class Meta:
        model = Post
        fields = ['id', 'title', 'content', 'author', 'post_type', 'metadata', 'created_at', 'likes', 'dislikes', 'comments']

    def get_author(self, obj):
        # Return a simplified author representation
        return {
            'id': obj.author.id,
            'username': obj.author.username,
            'email': obj.author.email
        }