from rest_framework import serializers
from .models import User, Post, Comment, Like

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

class PostSerializer(serializers.ModelSerializer):
    # Serialize the author as a nested object (using UserSerializer if available)
    author = serializers.SerializerMethodField()

    # Serialize likes as a list of like IDs or objects (depending on your needs)
    likes = serializers.PrimaryKeyRelatedField(many=True, read_only=True)

    class Meta:
        model = Post
        fields = ['id', 'title', 'content', 'author', 'post_type', 'metadata', 'created_at', 'likes']

    def get_author(self, obj):
        # Return a simplified author representation or use UserSerializer if defined
        return {
            'id': obj.author.id,
            'username': obj.author.username,
            'email': obj.author.email
        }