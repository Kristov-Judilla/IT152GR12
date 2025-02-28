import requests

url = "http://127.0.0.1:8000/posts/api/posts/"
headers = {
    "Authorization": "Token fb09e2d35667c7415fbf9817b1a2fb2d62f1f833",
    "Content-Type": "application/json"
}
data = {
    "post_type": "text",
    "title": "My First Post",
    "content": "Hello, world!"
}

response = requests.post(url, json=data, headers=headers)
print(response.json())