# Identity and Access Management System (deparja)

This project (deparja) provides an **Identity and Access Management (IAM)** system with basic user authentication, role management, and password reset features. The project leverages JWT (JSON Web Tokens) for secure API access and role-based access control (RBAC).

## Features (MVP)
- **User Management**
  - Create users
  - User login and JWT token generation
  - Password reset (generate reset token, reset password)
  
- **Role Management**
  - Create roles
  - Assign roles to users
  - Role-based access control (RBAC)

- **Security**
  - Password hashing (via `werkzeug.security`)
  - JWT-based authentication for secured endpoints

- **Permissions**: I’ve added roles, and manage permissions more precisely. For example, I've defined permissions like "create_user" or "view_reports" and assigned them to roles.
- **Access Control Logic**: I need to make sure users can only do what their roles and permissions allow. For instance, if someone tries to access `/api/secure-data`, I’ll add logic to check their permissions first.

- I need to fully implement JWT token validation. Endpoints that require a token, like `/api/secure-data`, should check if the token is valid and hasn’t expired. Some of this is done, but I’ll make sure it works consistently.

- **Error Handling & Responses**
- I’ll improve error messages to make them clear and user-friendly. Right now, some error cases, like missing data or invalid tokens, don’t have great responses.
- For `/api/roles` and `/api/user_roles`, I’ll handle duplicate roles or role assignments better by returning specific error messages (like "400 Bad Request").

- **User and Role Management**
- I’ll add features to update and delete users or roles, like `/api/users/{id}` or `/api/roles/{id}`.
- I’ll also allow removing role assignments, for example with `/api/user_roles/{user_id}/{role_id}`.

- **Password Hashing and Security**
- I already hash passwords before saving them, but I’ll double-check to ensure no plain-text passwords are ever exposed anywhere.


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

- **User login (Generate JWT token)**
  - `POST /api/login`
  - Request: 
    ```json
    { "username": "testuser", "password": "Test@1234" }
    ```
  - Response: 
    ```json
    { "access_token": "jwt_token", "refresh_token": "jwt_refresh_token" }
    ```

- **Password reset request**
  - `POST /api/password_reset_request`
  - Request: 
    ```json
    { "username": "testuser" }
    ```
  - Response: 
    ```json
    { "message": "Reset token sent" }
    ```

- **Reset password**
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
- **Create a role**
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

- **Assign a role to a user**
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
- **Check if user has a specific role**
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
- **Access secure data (requires valid JWT token)**
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
- **Password hashing** is used to securely store user passwords.
- **JWT Authentication**: Access protected routes by including a valid JWT token in the Authorization header.

## Missing or Needed Features for a Complete MVP

### Testing
- **Unit Tests**: I’ll write tests to check key features like creating users, assigning roles, and resetting passwords. This will make sure everything works as expected.
- **Security Testing**: I’ll test endpoints like `/api/secure-data` to ensure unauthorized users can’t get access. I’ll also make sure the password reset flow is safe from abuse.

### Logging and Monitoring
- I’ll set up logging to track problems like failed logins, expired tokens, and security issues. This will help with debugging and keeping the system secure.
- I’ll also think about adding rate-limiting or protection against brute-force attacks on the endpoints.

### Documentation
- I’ll document the API better with step-by-step instructions, like how to register, log in, reset passwords, and use roles and permissions.
- Tools like Swagger or Postman could help make the documentation easier to use.

## What’s Not Needed in the MVP (for now):

### Full-fledged User Interface (UI):
- A full UI with a front-end framework (e.g., React) is not essential for now - as we are building MVP. If your focus is on API functionality, the front-end could be minimal or nonexistent for now.

### Advanced Auditing and Logging:
- While logging is important, advanced auditing of user actions may not be necessary at the MVP stage.

### Complex Workflow for Permissions:
- For simplicity, start with a basic permissions structure and keep it flexible for future iterations.

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