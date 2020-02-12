from flask import Flask
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_oidc import OpenIDConnect

session = Session()
app = Flask(__name__, static_url_path='', static_folder='static')
csrf = CSRFProtect(app)
Config.read_config()
app.config.from_object(Config)
session.init_app(app)
oidc = OpenIDConnect(app)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

from app import routes, models, session

