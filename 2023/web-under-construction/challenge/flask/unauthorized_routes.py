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

from flask import Blueprint, render_template
from flask_login import login_required, current_user
from app import db

unauthorized = Blueprint('unauthorized', __name__)

@unauthorized.route('/')
def index():
    return render_template('index.html')

@unauthorized.route('/profile')
@login_required
def profile():
    return render_template('profile.html', username=current_user.username, tier=current_user.tier)
