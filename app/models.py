from . import db  # Import db from __init__.py
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta

# Users Table
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    password_reset_token = db.Column(db.String(256), nullable=True)
    reset_token_expiry = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_reset_token(self):
        self.password_reset_token = str(uuid.uuid4())
        self.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)

    def validate_reset_token(self, token):
        return self.password_reset_token == token and datetime.utcnow() < self.reset_token_expiry

# Roles Table
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String(50), unique=True, nullable=False)

# UserRoles Table
class UserRole(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)

    user = db.relationship('User', backref=db.backref('user_roles', lazy=True))
    role = db.relationship('Role', backref=db.backref('user_roles', lazy=True))
