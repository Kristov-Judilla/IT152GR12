# 🚀 Connectly - A Social Media Feed Application

<p align="center">

![Python](https://img.shields.io/badge/PYTHON-3.9+-323330?style=flat&logo=python&labelColor=323330&color=FFD43B)  
![Django](https://img.shields.io/badge/DJANGO-4.2+-323330?style=flat&logo=django&labelColor=323330&color=092E20)  
![SQLite](https://img.shields.io/badge/SQLITE-DATABASE-323330?style=flat&logo=sqlite&labelColor=323330&color=003B57)  
![Status](https://img.shields.io/badge/STATUS-COMPLETED-323330?style=flat&labelColor=323330&color=2ECC71)  
![Contributors](https://img.shields.io/badge/CONTRIBUTORS-4-323330?style=flat&labelColor=323330&color=F39C12)

</p>

---

## 📖 Course Overview: Integrative Programming and Technologies

**Connectly** is a social media app developed to learn integrative programming concepts. It involves building a cohesive system by integrating third-party services (e.g., Google OAuth for login), managing data relationships (e.g., users, posts, likes), and ensuring scalability, security, and performance. Key challenges include optimizing database queries, implementing caching, and ensuring secure authentication, all while maintaining a modular architecture. This course project helps you master integration, scalability, and system cohesion.

---

## 🛠️ Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Kristov-Judilla/IT152GR12.git
   cd IT152GR12
   ```

2. **Set Up a Virtual Environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Set Up Environment Variables**:
   - Create a `.env` file in the project root.
   - Add your Google OAuth credentials and other settings:
     ```env
     GOOGLE_CLIENT_ID=your-client-id
     GOOGLE_CLIENT_SECRET=your-client-secret
     SECRET_KEY=your-django-secret-key
     ```

5. **Run Migrations**:
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```

6. **Start the Development Server**:
   ```bash
   python manage.py runserver
   ```

---

## 🚀 Usage

1. **Authenticate with Google OAuth**:
   - Send a `POST` request to `/auth/google/login` with your Google OAuth token to authenticate and receive a token.

2. **Create a Post**:
   - Use the token in the `Authorization` header.
   - Send a `POST` request to `/posts/` with the post content:
     ```json
     {
         "content": "My first post!",
         "privacy": "public"
     }
     ```

3. **Retrieve the Feed**:
   - Send a `GET` request to `/feed/?page=1&size=10` to retrieve a paginated feed, filtered by privacy and user role.

---

## 🌟 Features

- **🔒 Google OAuth Authentication**: Securely authenticate users via Google OAuth.
- **📝 Post Creation**: Create posts with validated input and privacy settings.
- **📜 Personalized Feed**:
  - Paginated and sorted by `created_at` (descending).
  - Filters: `followed`, `liked`, `friends`.
  - Privacy settings: `public`, `private`, `friends`.
  - Role-based access control: `admin`, `moderator`, `regular user`.
- **⚡ Performance Optimizations**:
  - Caching with Redis (production) or LocMemCache (development).
  - Database indexing on `created_at` and `author_id`.
  - Query optimization with `select_related`, `prefetch_related`, and `only()`.
  - Logging of response times and cache hit rates.

---

## 📂 Project Structure

Below is the directory structure of the Connectly project:

- **connectly_project**
  - **connectly_project**
    - `__pycache__`
    - `__init__.py`
    - `asgi.py`
    - `settings.py`
    - `test_api.py`
    - `urls.py`
    - `wsgi.py`
  - **env**
  - **factories**
    - `__pycache__`
    - `post_factory.py`
  - **logs**
    - `feedview.log`
  - **posts**
    - `__pycache__`
    - `migrations`
    - `templates`
    - `__init__.py`
    - `admin.py`
    - `apps.py`
    - `models.py`
    - `permissions.py`
    - `serializers.py`
    - `tests.py`
    - `urls.py`
    - `views.py`
  - **singletons**
    - `__pycache__`

---

## 📦 Deliverables

The following deliverables are part of our project submission:

<div align="center">

| Deliverable         | Link                                                                                   |
|---------------------|----------------------------------------------------------------------------------------|
| Diagrams            | [View Diagrams](https://drive.google.com/file/d/1ou3W_1oy3tug2yCmEkv_6WByFDyMcQ9u/view?usp=sharing) |
| API Codebase        | [View Codebase](https://github.com/Kristov-Judilla/IT152GR12/)                        |
| Testing Evidence    | [View Testing Evidence](https://drive.google.com/drive/folders/1N_B7AJz7VQ6k56fTKS2VJYDUVu4CmKCj?usp=sharing) |

</div>

---

## 👥 Group Mates

Here’s the team behind Connectly! Edit the names, roles, and email addresses below:

- **[Your Full Name]** - Project Lead & Backend Developer - [your-email@example.com](mailto:your-email@example.com)
- **[Group Mate 1 Full Name]** - [Role/Contribution] - [groupmate1-email@example.com](mailto:groupmate1-email@example.com)
- **[Group Mate 2 Full Name]** - [Role/Contribution] - [groupmate2-email@example.com](mailto:groupmate2-email@example.com)
- **[Group Mate 3 Full Name]** - [Role/Contribution] - [groupmate3-email@example.com](mailto:groupmate3-email@example.com)

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## 📬 Contact

For questions or feedback, reach out to us at [your-email@example.com](mailto:your-email@example.com).

---

![Footer](https://img.shields.io/badge/Made%20with-❤️%20by%20Connectly%20Team-blue?style=for-the-badge)
