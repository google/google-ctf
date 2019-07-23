#
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
#

from flask import Flask, current_app, request, render_template, jsonify, make_response, redirect, url_for, send_file
from config import FLAG_XSS, FLAG_SSRF, TOKEN, ADMIN_TOKEN
from functools import wraps
import requests
import json
import os

from google.cloud import pubsub_v1
import google.auth.transport.requests


class NoProxyRequest(google.auth.transport.requests.Request):
  def __init__(self, session=None):
    super(NoProxyRequest, self).__init__(session)
    self.session.trust_env = False

# monkey patch
google.auth.transport.requests.origRequest = google.auth.transport.requests.Request
google.auth.transport.requests.Request = NoProxyRequest


app = Flask(__name__)
app.config["DEBUG"] = False

def admin_required(f):
  @wraps(f)
  def wrap(*args, **kwargs):
    token = request.cookies.get("auth")

    if token == ADMIN_TOKEN:
      return f(*args, **kwargs)
    else:
      return redirect(url_for('index'))

  return wrap

@app.route("/", methods=["GET"])
def index():
  token = request.cookies.get("auth")
  is_admin = token == ADMIN_TOKEN

  return render_template("index.html", HOSTNAME=request.host_url[:-1] , is_admin=is_admin)

@app.route("/admin", methods=["GET"])
@admin_required
def admin():
  return render_template("admin.html")

@app.route("/admin/users", methods=["GET"])
@admin_required
def admin_users():
  return render_template("admin.html")

@app.route("/admin/livestreams", methods=["GET"])
@admin_required
def admin_livestreams():
  return render_template("admin.html")

@app.route("/admin/controls", methods=["GET"])
def admin_controls():
  if request.remote_addr == "127.0.0.1":
    return render_template("admin_controls.html", HOSTNAME=request.host_url , FLAG=FLAG_SSRF)
  else:
    return "Requests only accepted from 127.0.0.1", 403


@app.route("/send", methods=["POST"])
def send():
  result = {"profile_url": "/static/img/profile.png",
            "username": "brewtoot",
           }
  blacklist = [
      "script",
      "alert",
      "iframe",
      "svg",
      "onload",
      "javascript",
      "onmouseover",
      "console",
  ]
  message = request.form["message"]
  if any([bad_word in message for bad_word in blacklist]):
    message = "HACKER ALERT!"
  elif "<" in message: # Spare xssbot useless messages
    xss(message)
  result["message"] = message
  return jsonify(result)

@app.route("/watch", methods=["GET"])
def watch():
  url = request.args.get('livestream')
  livestream = "livestream/garden-livestream.webm"
  HOSTNAME = request.host_url[:-1].replace('https', 'http')
  url = url.replace("https", "http")
  if not url.startswith(HOSTNAME):
    return render_template("forbidden.html", HOSTNAME=HOSTNAME), 403

  # fix DOS described in b/135421983
  if url.count(HOSTNAME) != 1:
    return "Where do you think you're going?", 404

  if url == HOSTNAME + "/" + livestream:
    return send_file(livestream)
  else:
    return str(requests.get(url).content)


@app.route("/exploit", methods=["GET"])
def exploit():
  return render_template("exploit.html")


def xss(message):
  HOSTNAME = 'https://' + request.host
  url = HOSTNAME + "/exploit?reflect=" + message
  publisher = pubsub_v1.PublisherClient()
  topic_path = publisher.topic_path(
        os.getenv('GOOGLE_CLOUD_PROJECT'),
        "xss")

  payload = {'url': url, 'service': 'cwo'}
  publisher.publish(topic_path, data=json.dumps(payload))

if __name__ == "__main__":
  app.run(host="0.0.0.0", threaded=True)
