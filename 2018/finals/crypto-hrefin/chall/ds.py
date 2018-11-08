#!/usr/bin/python
#
# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from google.cloud import datastore


def get_client():
    return datastore.Client(namespace='hrefin')

def delete(model):
    ds = get_client()

    q = ds.query(kind=model)

    for r in q.fetch():
        print r.key
        ds.delete(r.key)


def clean_db():
    ds = get_client()

    delete('Msg')
    delete('User')

