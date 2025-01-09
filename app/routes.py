from flask import Blueprint, request, jsonify
from .models import User, Role, Permission, UserRole, RolePermission
from .utils import generate_jwt, decode_jwt
from werkzeug.security import generate_password_hash, check_password_hash
from flask import current_app
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

bp = Blueprint('routes', __name__)
limiter = Limiter(
    get_remote_address,
    app=current_app,
    default_limits=["200 per day", "50 per hour"],  # Default rate limits
)

import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,  # Change to DEBUG for more verbosity
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("app.log"),  # Logs to a file
        logging.StreamHandler()         # Logs to the console
    ]
)


# Add User
@bp.route('/api/users', methods=['POST'])  # Corrected to allow POST
def add_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "User already exists"}), 400

    user = User(username=username)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User created", "user": {"id": user.id, "username": user.username}}), 201

@bp.route('/api/users/<int:id>', methods=['PUT'])
def update_user(id):
    data = request.json
    username = data.get('username')

    if not username:
        return jsonify({"error": "Username is required"}), 400

    user = User.query.get(id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    user.username = username
    db.session.commit()
    return jsonify({"message": "User updated", "user": {"id": user.id, "username": user.username}}), 200

@bp.route('/api/users/<int:id>', methods=['DELETE'])
def delete_user(id):
    user = User.query.get(id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "User deleted"}), 200


# Add Role
@bp.route('/api/roles', methods=['POST'])
def add_role():
    data = request.json
    role_name = data.get('role_name')

    if not role_name:
        return jsonify({"error": "Role name is required"}), 400

    if Role.query.filter_by(role_name=role_name).first():
        return jsonify({"error": "Role already exists"}), 400

    role = Role(role_name=role_name)
    db.session.add(role)
    db.session.commit()
    return jsonify({"message": "Role created", "role": {"id": role.id, "role_name": role.role_name}}), 201

@bp.route('/api/roles/<int:id>', methods=['PUT'])
def update_role(id):
    data = request.json
    role_name = data.get('role_name')

    if not role_name:
        return jsonify({"error": "Role name is required"}), 400

    role = Role.query.get(id)
    if not role:
        return jsonify({"error": "Role not found"}), 404

    role.role_name = role_name
    db.session.commit()
    return jsonify({"message": "Role updated", "role": {"id": role.id, "role_name": role.role_name}}), 200


@bp.route('/api/roles/<int:id>', methods=['DELETE'])
def delete_role(id):
    role = Role.query.get(id)
    if not role:
        return jsonify({"error": "Role not found"}), 404

    db.session.delete(role)
    db.session.commit()
    return jsonify({"message": "Role deleted"}), 200


# Assign Role to User
@bp.route('/api/user_roles', methods=['POST'])
def assign_role():
    data = request.json
    user_id = data.get('user_id')
    role_id = data.get('role_id')

    if not User.query.get(user_id):
        return jsonify({"error": f"User with ID {user_id} does not exist"}), 404

    if not Role.query.get(role_id):
        return jsonify({"error": f"Role with ID {role_id} does not exist"}), 404

    if UserRole.query.filter_by(user_id=user_id, role_id=role_id).first():
        return jsonify({"error": "Role already assigned to user"}), 400

    user_role = UserRole(user_id=user_id, role_id=role_id)
    db.session.add(user_role)
    db.session.commit()
    return jsonify({"message": "Role assigned to user", "user_role": {"user_id": user_id, "role_id": role_id}}), 201

@bp.route('/api/user_roles/<int:user_id>/<int:role_id>', methods=['DELETE'])
def remove_role_assignment(user_id, role_id):
    user_role = UserRole.query.filter_by(user_id=user_id, role_id=role_id).first()
    if not user_role:
        return jsonify({"error": "Role assignment not found"}), 404

    db.session.delete(user_role)
    db.session.commit()
    return jsonify({"message": "Role assignment removed"}), 200


# Check RBAC Permission
@bp.route('/api/check_permission', methods=['POST'])
def check_permission():
    data = request.json
    username = data.get('username')
    role_name = data.get('role_name')

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    role = Role.query.filter_by(role_name=role_name).first()
    if not role:
        return jsonify({"error": "Role not found"}), 404

    user_role = UserRole.query.filter_by(user_id=user.id, role_id=role.id).first()
    if user_role:
        return jsonify({"message": "Permission granted"}), 200
    else:
        return jsonify({"message": "Permission denied"}), 403


# Login
@bp.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")  # Limit login attempts
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({"error": "Invalid username or password"}), 401
    
    # Inside login route
    if not user or not user.check_password(password):
        logging.warning(f"Failed login attempt for username: {username}")
        return jsonify({"error": "Invalid username or password"}), 401


    access_token = generate_jwt({"user_id": user.id}, current_app.config["JWT_ACCESS_TOKEN_EXPIRES"])
    refresh_token = generate_jwt({"user_id": user.id}, current_app.config["JWT_REFRESH_TOKEN_EXPIRES"])
    return jsonify({"access_token": access_token, "refresh_token": refresh_token}), 200

# Refresh Token
@bp.route('/api/refresh', methods=['POST'])
def refresh_token():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    decoded = decode_jwt(token)

    if "error" in decoded:
        return jsonify(decoded), 401

    new_access_token = generate_jwt({"user_id": decoded["user_id"]}, current_app.config["JWT_ACCESS_TOKEN_EXPIRES"])
    return jsonify({"access_token": new_access_token}), 200

# Role-Based Access Control
def requires_permission(permission_name):
    def decorator(f):
        def wrapper(*args, **kwargs):
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
            decoded = decode_jwt(token)
            if "error" in decoded:
                return jsonify(decoded), 401

            user_id = decoded["user_id"]
            user = User.query.get(user_id)
            if not user:
                return jsonify({"error": "User not found"}), 404

            # Check if user has a role with the required permission
            permission = Permission.query.filter_by(permission_name=permission_name).first()
            if not permission:
                return jsonify({"error": "Permission not found"}), 404


            role_permissions = RolePermission.query.filter_by(permission_id=permission.id).all()
            role_ids_with_permission = [rp.role_id for rp in role_permissions]

            if not any(UserRole.query.filter_by(user_id=user_id, role_id=role_id).first() for role_id in role_ids_with_permission):
                return jsonify({"error": "Permission denied"}), 403

            return f(*args, **kwargs)
        return wrapper
        # Inside requires_permission decorator
        if not any(UserRole.query.filter_by(user_id=user_id, role_id=role_id).first() for role_id in role_ids_with_permission):
            logging.warning(f"Permission denied for user_id: {user_id} for permission: {permission_name}")
            return jsonify({"error": "Permission denied"}), 403
    return decorator

@bp.route('/api/secure-data', methods=['GET'])
@requires_permission('view_secure_data')
def secure_data():
    return jsonify({"message": "This is secure data for users with the correct permission."}), 200

@bp.route('/api/password_reset_request', methods=['POST'])
def request_password_reset():
    data = request.json
    username = data.get('username')
    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    user.generate_reset_token()
    db.session.commit()
    # Simulate sending email
    return jsonify({"message": "Password reset link sent", "reset_token": user.password_reset_token}), 200

@bp.route('/api/password_reset', methods=['POST'])
def reset_password():
    data = request.json
    reset_token = data.get('reset_token')
    new_password = data.get('new_password')

    user = User.query.filter_by(password_reset_token=reset_token).first()

    if not user or not user.validate_reset_token(reset_token):
        return jsonify({"error": "Invalid or expired reset token"}), 400

    user.set_password(new_password)
    user.password_reset_token = None
    user.reset_token_expiry = None
    db.session.commit()
    return jsonify({"message": "Password reset successful"}), 200


# Create a Permission
@bp.route('/api/permissions', methods=['POST'])
def add_permission():
    data = request.json
    permission_name = data.get('permission_name')

    if not permission_name:
        return jsonify({"error": "Permission name is required"}), 400

    if Permission.query.filter_by(permission_name=permission_name).first():
        return jsonify({"error": "Permission already exists"}), 400

    permission = Permission(permission_name=permission_name)
    db.session.add(permission)
    db.session.commit()
    return jsonify({"message": "Permission created", "permission": {"id": permission.id, "name": permission.permission_name}}), 201

# Assign a Permission to a Role
@bp.route('/api/role_permissions', methods=['POST'])
def assign_permission_to_role():
    data = request.json
    role_id = data.get('role_id')
    permission_id = data.get('permission_id')

    if not role_id or not permission_id:
        return jsonify({"error": "Role ID and Permission ID are required"}), 400

    if RolePermission.query.filter_by(role_id=role_id, permission_id=permission_id).first():
        return jsonify({"error": "Permission already assigned to role"}), 400

    role_permission = RolePermission(role_id=role_id, permission_id=permission_id)
    db.session.add(role_permission)
    db.session.commit()
    return jsonify({"message": "Permission assigned to role", "role_permission": {"role_id": role_id, "permission_id": permission_id}}), 201
