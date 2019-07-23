#!/usr/bin/env python3
#
# Copyright 2019 Google LLC
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
# limitations under the License.import requests
#

from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from geopy.distance import geodesic
from flask import Flask, render_template, request

app = Flask(__name__)

STARTING_POINT = (51.6498, 0.0982)
DESTINATION_POINT = (51.4921, -0.1929)
MAX_STEP_DISTANCE = 300  # no more than 300 meters per step
MAX_SPEED_KMPH = 50 # 50 km/h. It will take under an hour to drive from start to destination.
FINISH_RADIUS = 10 # If the point is within 10m from DESTINATION_POINT then FLAG is shown
FLAG = ' CTF{Who_is_Tardis_Ormandy}'

f = Fernet(b'l4ydYP_3aH8n7uQR2EIHgt-jfhhL7U6-yurXBeE89Do=')

def parse_state(state):
    lat, lon, time = tuple(map(float, state.split(',')))
    return (lat, lon), datetime.fromtimestamp(time)

@app.route('/')
def process():
    try:
        time = datetime.now()
        if 'token' not in request.args:
            token = f.encrypt(('%f,%f,%f' % (STARTING_POINT[0], STARTING_POINT[1],time.timestamp())).encode()).decode()
            return render_template('ui.html', lat=STARTING_POINT[0], lon=STARTING_POINT[1], token=token)

        old_token = request.args.get('token')
        pos = float(request.args.get('lat')), float(request.args.get('lon'))

        old_pos, old_time = parse_state(f.decrypt(old_token.encode()).decode())
        distance = geodesic(old_pos, pos)
        hours = (time - old_time) / timedelta(hours=1)
        speed_kmph = distance.kilometers / hours if hours > 0 else 10 * MAX_SPEED_KMPH # if time == old_time, e.g. hours == 0, then we say that player has moved infinitely fast, e.g. 10 max speeds.
        next_pos, next_token = old_pos, old_token

        msg = ''
        if old_pos == pos:
            msg = 'If you want to meet your friends, you should move.'
        elif speed_kmph > MAX_SPEED_KMPH:
            msg = 'Woa, were about to move at %dkm/h, this is too fast!' % speed_kmph
        elif distance.meters > MAX_STEP_DISTANCE:
            msg = 'You tried to travel %dm, which too far at once from your current position.' % distance.meters
        else:
            if geodesic(pos, DESTINATION_POINT).meters < FINISH_RADIUS:
                msg = 'Congratulations, you made it, here is the flag: %s' % FLAG
            elif geodesic(pos, DESTINATION_POINT) < geodesic(old_pos, DESTINATION_POINT):
                msg = 'You went %dm at a speed of %dkm/h. You are getting closer…' % (distance.meters, speed_kmph)
            else:
                msg = 'You went %dm at a speed of %dkm/h. You are getting away…' % (distance.meters, speed_kmph)
            next_token = f.encrypt(('%f,%f,%f' % (pos[0], pos[1],time.timestamp())).encode()).decode()
            next_pos = pos
        return render_template('ui.html', lat=next_pos[0], lon=next_pos[1], token=next_token, message=msg)
    except Exception as e:
        print(e)
        return 'Please use roads.'
