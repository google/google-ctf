# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from flask import Flask, request, render_template, abort, redirect, session
from functools import wraps
from base64 import b64encode
import requests
import json

from util import rand_name, copy, game_url

app = Flask(__name__, static_url_path="", static_folder="static")
app.config["SECRET_KEY"] = rand_name(40)


def game_session(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("game"):
            return redirect("/")
        return f(*args, **kwargs)

    return decorated_function


@app.route("/")
def index():
    if not session.get("game"):
        name = rand_name(10)
        game_r = requests.post(game_url("game"), json={"name": name})
        if game_r.status_code != 200:
            abort(400)
        session["game"] = game_r.json()
        session["items"] = json.dumps({}).encode()
    return render_template("index.html")


@app.route("/play", methods=["GET", "POST"])
@game_session
def play():
    game = session.get("game")
    if request.method == "GET":
        return render_template(
            "game.html",
            ev_title=game["ev_title"],
            ev_desc=game["ev_desc"],
            ev_choice=game["ev_choice"],
        )
    else:
        data = request.json
        items = ""
        if session["items"] is not None:
            items = b64encode(session["items"]).decode()
        game_r = requests.post(
            game_url("event"),
            json={"name": game["player"], "choice": data.get("choice"), "items": items},
        )
        if game_r.status_code != 200:
            abort(400)
        session["game"] = game_r.json()
        if game_r.json().get("ev_item") is not None:
            item_name = game_r.json().get("ev_item")
            items = json.loads(session["items"].decode())
            items[item_name] = 1
            session["items"] = json.dumps(items).encode()
        return "success"


class ScoreSubmission:
    def __init__(self, name=rand_name(10), items={}):
        self.name = name
        self.items = items

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


@app.route("/score", methods=["POST"])
@game_session
def submit():
    score = ScoreSubmission(session["game"]["player"])
    copy(request.json, score)

    acquired_items = json.loads(session["items"].decode())
    score.items = acquired_items
    return score.toJSON()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=1338)
