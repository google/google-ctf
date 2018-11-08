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

import base64
from functools import wraps
import logging
import os
import sys

import werkzeug.serving
from flask import Flask, request, render_template, jsonify, redirect, abort
from google.cloud import datastore
from twisted.web.wsgi import WSGIResource
from twisted.internet import ssl, reactor
from twisted.web.http import HTTPChannel
from twisted.web.server import Site
from twisted.internet.protocol import Factory, Protocol
from OpenSSL import SSL
import OpenSSL.crypto

import cert
import api
import config


class MyHTTPChannel(HTTPChannel):
  def allHeadersReceived(self):

    cert = self.transport.getPeerCertificate()
    der = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert.to_cryptography())

    req = self.requests[-1]

    req.requestHeaders.removeHeader('X-User')
    req.requestHeaders.removeHeader('X-Cert')

    req.requestHeaders.addRawHeader('X-User', base64.b64encode(cert.get_subject().commonName))
    req.requestHeaders.addRawHeader('X-Cert', base64.b64encode(der))

    logging.info(repr(cert.get_subject().commonName))
    logging.info(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert.to_cryptography()))

    HTTPChannel.allHeadersReceived(self)


class MySite(Site):
  protocol = MyHTTPChannel

class CtxFactory(ssl.ClientContextFactory):
    def getContext(self):
        self.method = SSL.SSLv23_METHOD
        ctx = ssl.ClientContextFactory.getContext(self)
        ctx.use_certificate_file(cert.DOMAIN_PEM)
        ctx.use_privatekey_file(cert.DOMAIN_KEY)

        ctx.set_verify(
            SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT | SSL.VERIFY_CLIENT_ONCE,
            cert.verifyCallback
        )
        ctx.load_verify_locations('ca.pem')

        return ctx

def twist():
    reactor_args = {}
    flask_site = WSGIResource(reactor, reactor.getThreadPool(), app)

    sample_site = MySite(flask_site)

    if config.DEBUG:
        reactor_args['installSignalHandlers'] = 0

    reactor.listenSSL(config.HTTPS_PORT, sample_site, CtxFactory())
    reactor.run(**reactor_args)


def ssl_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not request.is_secure:
            return redirect(
                request.url.replace('http://', 'https://', 1).replace(str(config.HTTP_PORT), str(config.HTTPS_PORT), 1)
            )
        else:
            return f(*args, **kwargs)
    return decorated_function

app = Flask(__name__)


@app.route('/admin')
@ssl_required
def admin():
    user = cert.parse_cert(request.headers['X-Cert'].decode('base64'), True)

    if user['name'].lower() == 'admin':
        return 'Congratulations the flag is %s' % config.FLAG

    return "You're not admin, you're %s." % user['name'].lower(), 403

@app.route('/send', methods=['POST'])
@ssl_required
def send():
    user = cert.parse_cert(request.headers['X-Cert'].decode('base64'), True)

    if 'user' not in request.form or 'msg' not in request.form:
        abort(400)
    api.send_msg(request.form['user'], user['name'], request.form['msg'])

    return redirect('/profile')

@app.route('/profile')
@ssl_required
def profile():
    user = cert.parse_cert(request.headers['X-Cert'].decode('base64'), True)
    #user = request.headers['X-User'].decode('base64')
    return render_template('profile.html', user=user, messages=api.get_messages(user['name']))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        return jsonify(api.register(request.form['csr']))

    return render_template('register.html', ca_pem=base64.b64encode(cert.get_ca_cert()))

@app.route('/login')
def login():
    if not request.is_secure:
        return redirect(
            request.url_root.replace('http://', 'https://', 1).replace(str(config.HTTP_PORT), str(config.HTTPS_PORT), 1)
        )
    else:
        return redirect('/profile')

@app.route('/')
def index():
    return render_template('index.html', is_secure=request.is_secure)


if __name__ == '__main__':
    cert.setup(config.DOMAIN)
    if len(sys.argv) > 1 and sys.argv[1] == 'ssl':
        if (config.DEBUG):
            import werkzeug.serving
            werkzeug.serving.run_with_reloader(twist)
        else:
            twist()
    else:
        app.run(host='127.0.0.1', port=config.HTTP_PORT, debug=config.DEBUG)
