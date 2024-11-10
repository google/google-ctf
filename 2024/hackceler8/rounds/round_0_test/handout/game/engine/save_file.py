# Copyright 2024 Google LLC
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
import json
import logging
import os
import time

from game.components.items import load_items_from_save, display_to_name, check_item_loaded


class SaveFile:

  def __init__(self, filename, version, extra_items):
    self.filename = filename
    self.version = version
    self.extra_items = extra_items

  def save(self, game):
    if not game.is_server:
      return
    logging.info('Dumping save')
    tmp_save_file = f'{self.filename}.tmp'

    _save = {
        'version': self.version,
        'flags': game.match_flags.dump(),
        'items': [i.dump() for i in game.items],
        'coins': len([i for i in game.items if i.name.startswith("coin_")]),
        'stars_for_boss': game.match_flags.stars_for_boss,
        'save_time': time.time(),
        'win_time': game.win_timestamp,
    }

    with open(tmp_save_file, 'w') as f:
      f.write(json.dumps(_save))
    os.replace(tmp_save_file, self.filename)

  def load(self):
    with open(self.filename) as sf:
      current_save = sf.read()
    payload = json.loads(current_save)
    for k in ['version', 'flags', 'coins', 'items', 'stars_for_boss', 'win_time', 'save_time']:
      if k not in payload:
        logging.critical(f'Missing property {k} in save file')
        return None
    if self.extra_items is not None:
      items = payload["items"]
      for d in self.extra_items:
        if not any([i["display_name"] == d for i in items]):
          items.append(
              {"name": display_to_name(d), "display_name": d, "collected_time": time.time()},
          )
    return payload

def apply_save_state(state, game):
  if state is None:
    return
  if "flags" in state:
    for f in state["flags"]:
      if f["collected_time"] > 0:
        game.match_flags.obtain_flag(f["name"], f["collected_time"])
  if "items" in state:
    game.items = load_items_from_save(state["items"])
  if "win_timestamp" in state:
    game.win_timestamp = state["win_timestamp"]
