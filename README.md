# Identity and Access Management System (Deparja)

Deparja provides an **Identity and Access Management (IAM)** system with basic user authentication, role management, and password reset features. The project leverages JWT (JSON Web Tokens) for secure API access and role-based access control (RBAC).

## Features (MVP)
### 1. User Management
- **Create Users**: Add new users to the system.
- **User Login & JWT Token Generation**: Secure login with JWT authentication.
- **Password Reset**: Request a password reset and reset the password.

### 2. Role Management
- **Create Roles**: Add roles like "admin", "user", etc.
- **Assign Roles to Users**: Assign roles to users for access control.
- **Role-Based Access Control (RBAC)**: Protect API endpoints using roles.

### 3. Permission Management
- **Permissions Assignment**: Assign permissions like `create_user`, `view_reports` to roles.

### 4. Security Features
- **Password Hashing**: Passwords are hashed for security using `werkzeug.security`.
- **JWT Authentication**: Use JWT for protecting endpoints.

### 5. Logging & Monitoring
- **Logging**: Track failed login attempts, expired tokens, and security issues.
- **Rate-Limiting**: Prevent brute-force attacks with rate-limiting for API endpoints.

### 6. Error Handling & Responses
- Improved error messages for cases like missing data or invalid tokens.
- Handle role duplication or assignment issues with specific error messages like "400 Bad Request".

### 7. User & Role Management Enhancements
- **Update and Delete Users**: Modify or remove users through endpoints like `/api/users/{id}`.
- **Update and Delete Roles**: Modify or remove roles using `/api/roles/{id}`.
- **Remove Role Assignments**: Remove roles from users via `/api/user_roles/{user_id}/{role_id}`.

## Endpoints

### 1. User Management
- **Create a new user**
  - `POST /api/users`
  - Request: 
    ```json
    { "username": "testuser", "password": "Test@1234" }
    ```
  - Response: 
    ```json
    { "message": "User created", "user": { "id": 1, "username": "testuser" } }
    ```

- **User Login (Generate JWT token)**
  - `POST /api/login`
  - Request:
    ```json
    { "username": "testuser", "password": "Test@1234" }
    ```
  - Response:
    ```json
    { "access_token": "jwt_token", "refresh_token": "jwt_refresh_token" }
    ```

- **Password Reset Request**
  - `POST /api/password_reset_request`
  - Request:
    ```json
    { "username": "testuser" }
    ```
  - Response:
    ```json
    { "message": "Reset token sent" }
    ```

- **Reset Password**
  - `POST /api/password_reset`
  - Request:
    ```json
    { "reset_token": "your_reset_token", "new_password": "NewPass@1234" }
    ```
  - Response:
    ```json
    { "message": "Password reset successfully" }
    ```

### 2. Role Management
- **Create a Role**
  - `POST /api/roles`
  - Request:
    ```json
    { "role_name": "admin" }
    ```
  - Response:
    ```json
    { "message": "Role created", "role": { "id": 1, "role_name": "admin" }}
    ```
  - **Error:**
    ```json
    { "error": "Role already exists" }
    ```

- **Assign a Role to a User**
  - `POST /api/user_roles`
  - Request:
    ```json
    { "user_id": 1, "role_id": 1 }
    ```
  - Response:
    ```json
    { "message": "Role assigned to user" }
    ```
  - **Error:**
    ```json
    { "error": "Role already assigned to user" }
    ```

### 3. Permission Check
- **Check if User has a Specific Role**
  - `POST /api/check_permission`
  - Request:
    ```json
    { "username": "testuser", "role_name": "admin" }
    ```
  - Response:
    ```json
    { "message": "Permission granted" }
    ```
    or
    ```json
    { "message": "Permission denied" }
    ```

### 4. Secure Endpoint (JWT Protected)
- **Access Secure Data (requires valid JWT token)**
  - `GET /api/secure-data`
  - Headers: `Authorization: Bearer your_jwt_token`
  - Response:
    ```json
    { "secure_data": "This is protected data" }
    ```
  - **Error:**
    ```json
    { "error": "Invalid token" }
    ```

## Security Features
- **Password Hashing**: Ensures that user passwords are stored securely.
- **JWT Authentication**: Used for securing API endpoints and ensuring only authorized users can access them.

## How to Run
1. Clone the repository:
   ```bash
   git clone <repository_url>
   cd <project_directory>

2. Install dependencies:
    ```bash
    pip install -r requirements.txt
3. Run the Flask app:
    ```bash
    flask run
4. API will be accessible at  ```http://127.0.0.1:5000.```