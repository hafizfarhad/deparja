def validate_request_keys(data, required_keys):
    missing_keys = [key for key in required_keys if key not in data]
    if missing_keys:
        return {"error": f"Missing keys: {', '.join(missing_keys)}"}
    return None

import jwt
from datetime import datetime, timedelta
from flask import current_app

def generate_jwt(data, expiry, secret=None):
    expiry_date = datetime.utcnow() + timedelta(seconds=expiry)
    token = jwt.encode({"exp": expiry_date, **data}, secret or current_app.config["SECRET_KEY"], algorithm="HS256")
    return token

def decode_jwt(token, secret=None):
    try:
        decoded = jwt.decode(token, secret or current_app.config["SECRET_KEY"], algorithms=["HS256"])
        return decoded
    except jwt.ExpiredSignatureError:
        return {"error": "Token has expired"}
    except jwt.InvalidTokenError:
        return {"error": "Invalid token"}

import re

def validate_password(password):
    if len(password) < 8:
        return "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return "Password must contain at least one lowercase letter"
    if not re.search(r'[0-9]', password):
        return "Password must contain at least one digit"
    if not re.search(r'[@$!%*?&#]', password):
        return "Password must contain at least one special character"
    return None
