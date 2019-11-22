# Copyright 2019 Google LLC
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

from django.utils.text import slugify
import hashlib
import os


class UserMiddleware:
  def __init__(self, get_response):
    self.get_response = get_response

  def __call__(self, request):
    user_id = request.COOKIES.get('user')
    if not user_id:
      user_id = hashlib.md5(os.urandom(16)).hexdigest()
    else:
      user_id = slugify(user_id)

    user_dir = os.path.join('media', user_id)

    if not os.path.exists(user_dir):
      os.makedirs(user_dir)
      os.makedirs(os.path.join(user_dir, 'thumbs'))

    request.user_id = user_id

    response = self.get_response(request)
    response.set_cookie('user', user_id)

    return response
