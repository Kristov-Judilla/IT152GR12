from posts.models import Post

# factories/post_factory.py
from posts.models import Post

class PostFactory:
    @staticmethod
    def create_post(post_type, title, content, metadata, author, privacy='public'):
        if post_type not in ['text', 'image', 'video']:
            raise ValueError("Invalid post type. Must be 'text', 'image', or 'video'.")
        
        post = Post.objects.create(
            post_type=post_type,
            title=title,
            content=content,
            metadata=metadata,
            author=author,
            privacy=privacy  # Ensure privacy is set
        )
        return post