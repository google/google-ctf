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
import dill
import json
import logging
import os
import time

from components.magic_items import Item, load_item_from_save


class SaveFile:
    def __init__(self, filename='save_state'):
        self.filename = filename

    def save(self, game):
        logging.info("Dumping save")
        tmp_save_file = f"{self.filename}.tmp"

        d = {}
        for i in game.global_match_items.dump():

            d[i["name"]] = i
        _save = {
            'items': d,
            'save_time': time.time(),
            'win_time': game.win_timestamp,
        }
        if game.boss_llm_exists:
            _save['boss_llm_time'] = game.boss_llm_win_time
        if game.boss_danmaku_exists:
            _save['boss_llm_time'] = game.boss_danmaku_win_time

        with open(tmp_save_file, 'w') as f:
            f.write(json.dumps(_save))
        os.replace(tmp_save_file, self.filename)

    def load(self, preload_items=False):
        sf = open(self.filename)
        current_save = sf.read()
        sf.close()
        payload = json.loads(current_save)
        for k in ['items', 'win_time', 'save_time']:
            if k not in payload:
                logging.critical(f"Missing property {k} in save file")
                return None
        if not preload_items:
            return payload
        return self.parse(payload)

    @staticmethod
    def parse(payload):
        if payload['win_time'] > 0:
            logging.info("Player already won")
        else:
            logging.info("Player has not won yet")

        _items = []
        for _i in payload['items']:
            i = payload['items'][_i]
            it = load_item_from_save(i['name'], i['display_name'], i['color'],
                                     i['wearable'], i['collected_time'])
            if it.collected_time > 0:
                _items.append(it)
        return _items, payload['win_time'], payload['save_time']


def check_item_loaded(items: list[Item], item) -> bool:
    if item is None:
        return False
    for i in items:
        if i.is_identical(item):
            return True
    return False
