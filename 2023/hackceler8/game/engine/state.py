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
import logging
import dill

from components.magic_items import Item, load_from_save


def load_from_savefile(load_file):
    loaded_items = []
    logging.info(f"Loading from save, using save_file {load_file}")
    try:
        parsed = open(load_file, 'rb').read().split(b'\xfe\xfe')
    except Exception as e:
        logging.critical(f"Unable to load file {load_file}: {e}")
        return loaded_items
    ts = parsed[-1]
    logging.info(f"Time of save is {parsed[-1]}")
    if len(parsed) == 1:
        logging.info("No items in save")
        return loaded_items
    items_raw = parsed[:-1]
    items_parsed = [dill.loads(i) for i in items_raw]
    logging.info(items_parsed)
    logging.info(f"Loading a total of {len(parsed) - 1} objects.")
    for it in items_parsed:
        logging.info(f"Loading item {it[1:]}")
        loaded_items.append(load_from_save(*it[1:]))
    logging.info("Load complete!")
    return loaded_items


def check_item_loaded(items: list[Item], item) -> bool:
    if item is None:
        return False
    for i in items:
        if i.is_identical(item):
            return True
    return False
