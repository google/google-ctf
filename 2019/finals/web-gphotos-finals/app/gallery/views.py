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

from django.http import HttpResponse, HttpResponseRedirect # noqa: 401
from django.shortcuts import render
from django.core.files.storage import FileSystemStorage

from wand.image import Image

import os
import imghdr

from .forms import ImageForm


def index(request):
  try:
    images = os.listdir(os.path.join('media/{user_id}/thumbs/'\
      .format(user_id=request.user_id)))
  except:
    images = []

  return render(request, 'gallery/index.html',\
    {'user_id': request.user_id, 'images': images})


def new(request):
  form = ImageForm()

  if request.method == 'POST':
    form = ImageForm(request.POST, request.FILES)

    if form.is_valid():
      file = request.FILES['image']
      parts = os.path.splitext(file.name)
      location = os.path.join('media', request.user_id)

      fs = FileSystemStorage(location=location)
      filename = fs.save('{base}{extension}'.format(base=parts[0],\
        extension=parts[1]), file)
      original_path = os.path.join('media', request.user_id, filename)

      with Image(filename=original_path) as img:
        with img.clone() as image:
          image.transform(resize='x150')
          image.format = imghdr.what(original_path)
          thumb_path = os.path.join('media', request.user_id, 'thumbs',\
            filename)
          image.save(filename=thumb_path)

      return HttpResponseRedirect('/')

  return render(request, 'gallery/new.html', {'form': form})
