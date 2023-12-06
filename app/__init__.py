from flask import Flask
from flask_session import Session 
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from mongoengine import connect, disconnect

from config import Config, TestConfig

import os

session = Session()
login_manager= LoginManager()
SECRET_KEY = os.urandom(32)

def create_app(config=None):  
    app = Flask(__name__) 
    
    csrf = CSRFProtect(app)
    app.config['SECRET_KEY'] = SECRET_KEY
    app.config['WTF_CSRF_SECRET_KEY'] = SECRET_KEY
    app.config['WTF_CSRF_ENABLED'] = True
    csrf.init_app(app)

    with app.app_context():
        if config is not None:
            app.config.from_object(config)
        else: app.config.from_object(Config)

        disconnect(alias='default')

        connect(
            db=app.config['DB'],
            alias='default',
            host=app.config['MONGODB_HOST'],
            
        )

        session.init_app(app)
        login_manager.init_app(app)  
        login_manager.login_view = 'authorization.login'

        from app.main import bp as main_bp
        app.register_blueprint(main_bp)

        from app.errors import bp as errors_bp
        app.register_blueprint(errors_bp)

        from app.posts import posts_bp
        app.register_blueprint(posts_bp, url_prefix='/blog')
        
        from app.authorization import auth_bp
        app.register_blueprint(auth_bp)
    
    return app

