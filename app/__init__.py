from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from .config import config  # Import the config object

# Initialize the database and migrations
db = SQLAlchemy()  # db initialized here
migrate = Migrate()

def create_app():
    app = Flask(__name__)
    app.config.from_object(config["development"])  # Switch to production as needed
    app.debug = True
    # Use a relative path for the SQLite database
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Set a secret key (should be more secure in production)
    app.secret_key = "your_secret_key"  # Change this in production

    # Initialize the app with SQLAlchemy and Flask-Migrate
    db.init_app(app)  # Initialize the db here
    migrate.init_app(app, db)

    # Import and register routes blueprint
    from .routes import bp as routes_bp
    app.register_blueprint(routes_bp)

    return app
