from flask import Flask
from app.routes.scanner import scanner_bp

def create_app():
    app = Flask(__name__)
    
    # Register blueprints
    app.register_blueprint(scanner_bp)
    
    return app
