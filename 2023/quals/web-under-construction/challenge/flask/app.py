# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import gevent.monkey
gevent.monkey.patch_all()

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
import requests
import os

db = SQLAlchemy()

PHP_HOST = 'under-construction-php'
TOKEN = os.environ.get('MIGRATOR_TOKEN','missing_token')
MYSQL_USER = os.environ.get('MYSQL_USER')
MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD')
MYSQL_DATABASE = os.environ.get('MYSQL_DATABASE')
DB_HOST = os.environ.get('DB_HOST')

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ['FLASK_SECRET_KEY']
    app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{DB_HOST}/{MYSQL_DATABASE}'

    db.init_app(app)
    import models
    import authorized_routes
    import unauthorized_routes

    with app.app_context():
        db.create_all()

    login_manager = LoginManager()
    login_manager.login_view = 'authorized_routes.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return models.User.query.get(int(user_id))
    
    app.register_blueprint(authorized_routes.authorized)
    app.register_blueprint(unauthorized_routes.unauthorized)

    @app.cli.command("reset_db")
    def reset_db():
        with app.app_context():
            models.User.query.delete()
            db.session.commit()
        requests.post(f"http://{PHP_HOST}:1337/account_cleanup.php", headers={"token": TOKEN})

    return app
