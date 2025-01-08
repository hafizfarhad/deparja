import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "your_default_secret_key")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///app.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_ACCESS_TOKEN_EXPIRES = 3600  # 1 hour
    JWT_REFRESH_TOKEN_EXPIRES = 86400  # 1 day

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False
    
class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"  # In-memory DB for testing
    SECRET_KEY = "test-secret-key"
    JWT_ACCESS_TOKEN_EXPIRES = 300
    JWT_REFRESH_TOKEN_EXPIRES = 3600

config = {
    "development": DevelopmentConfig,
    "production": ProductionConfig
}
