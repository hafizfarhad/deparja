from flask import Blueprint, request, jsonify
from .models import db, User, Role, UserRole
from .utils import generate_jwt, decode_jwt
from werkzeug.security import generate_password_hash, check_password_hash
from flask import current_app

bp = Blueprint('routes', __name__)

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

# Assign Role to User
@bp.route('/api/user_roles', methods=['POST'])
def assign_role():
    data = request.json
    user_id = data.get('user_id')
    role_id = data.get('role_id')

    if not user_id or not role_id:
        return jsonify({"error": "User ID and Role ID are required"}), 400

    if UserRole.query.filter_by(user_id=user_id, role_id=role_id).first():
        return jsonify({"error": "Role already assigned to user"}), 400

    user_role = UserRole(user_id=user_id, role_id=role_id)
    db.session.add(user_role)
    db.session.commit()
    return jsonify({"message": "Role assigned to user", "user_role": {"user_id": user_id, "role_id": role_id}}), 201

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
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
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
def requires_role(role_name):
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

            role = Role.query.filter_by(role_name=role_name).first()
            if not role:
                return jsonify({"error": "Role not found"}), 404

            if not UserRole.query.filter_by(user_id=user_id, role_id=role.id).first():
                return jsonify({"error": "Permission denied"}), 403

            return f(*args, **kwargs)
        return wrapper
    return decorator

@bp.route('/api/secure-data', methods=['GET'])
@requires_role('admin')
def secure_data():
    return jsonify({"message": "This is secured data for admins only."}), 200

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
