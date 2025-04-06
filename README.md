# 🚀 Connectly - A Social Media Feed Application

![Connectly Banner](https://img.shields.io/badge/Connectly-Social%20Media%20Feed-blueviolet?style=for-the-badge&logo=appveyor)  
![Python](https://img.shields.io/badge/Python-3.9+-yellow?style=flat-square&logo=python)  
![Django](https://img.shields.io/badge/Django-4.2+-green?style=flat-square&logo=django)  
![SQLite](https://img.shields.io/badge/SQLite-Database-lightgrey?style=flat-square&logo=sqlite)

---

## 📖 About the Project

Connectly is a social media feed application built with Django, allowing users to create posts, retrieve personalized feeds, and interact securely with role-based access control and privacy settings. This project was developed as part of a coursework assignment, with key enhancements added in Homework 8 (Privacy Settings and RBAC) and Homework 9 (Performance Optimization).

---


## 🛠️ Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/your-username/connectly.git
   cd connectly
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

## 👥 Group Mates

Here’s the team behind Connectly! Feel free to add your group mates’ names below:

- **[Your Name]** - Project Lead & Backend Developer
- **[Group Mate 1]** - [Role/Contribution]
- **[Group Mate 2]** - [Role/Contribution]
- **[Group Mate 3]** - [Role/Contribution]

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## 📬 Contact

For questions or feedback, reach out to us at [your-email@example.com](mailto:your-email@example.com).

---

![Footer](https://img.shields.io/badge/Made%20with-❤️%20by%20Connectly%20Team-blue?style=for-the-badge)
