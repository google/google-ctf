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
from flask import request, jsonify
import cert
import hashlib


def get_client():
    return datastore.Client(namespace='hrefin')

def h256(s):
    return hashlib.sha256(s.encode('utf-8')).hexdigest()

def create_user(username):
    assert username.lower() != 'admin'

    ds = get_client()
    key = ds.key('User', h256(username))

    if ds.get(key) is not None:
        return False

    entity = datastore.Entity(key)
    ds.put(entity)

    return True

def get_messages(username):
    ds = get_client()

    q = ds.query(kind='Msg')
    q.add_filter('to', '=', h256(username))
    q.order = ['msg', 'from'];

    return list(q.fetch())

def send_msg(to, sender, msg):
    ds = get_client()
    key = ds.key('Msg')

    entity = datastore.Entity(key)

    entity.update({
        'to': h256(to),
        'msg': msg[:250],
        'from': sender
    })

    ds.put(entity)

def register(csr):

    try:
        data = cert.parse_csr(csr)
    except ValueError:
        return {'error': 'invalid_cert'}

    if not data.get('name'):
        return res

    res = cert.sign_csr(csr)

    if 'error' in res:
        return res

    if not create_user(data['name']):
        res = {'error': 'user_exists'}


    return res
