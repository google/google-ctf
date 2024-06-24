#!/usr/bin/python3
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
"""Python Storage Challenage

What a simple DB and CLI! It can never go wrong.
"""

import hmac
import io
import pathlib
import re
import secrets
import sys
import tempfile


class TextDatabase:
  """A database class using text file as storage for key/value pairs."""

  def __init__(self, storage_file: pathlib.Path, max_size: int):
    """Construct a TextDatabase upon the text file given.

    Args:
      storage_file: The file used as storage. If it does not already exist, one
        will be created.
      max_size: The maximum size in byte the storage can grow. Any operation
        causing the storage to grow above the limit will fail.
    """
    self._storage_file = storage_file
    self._max_size = max_size

    self._storage_file.touch()

  def add(self, key: str, value: str) -> bool:
    """Add a new pair of key/value into the storage.

    Args:
      key: The key of the pair.
      value: The value of the pair.

    Returns:
      A boolean indicating whether the operation success.
    """
    if ':' in key or '\n' in key or '\n' in value:
      return False
    entry = f'{key}:{value}\n'

    current_size = self._storage_file.stat().st_size
    if current_size + len(entry) > self._max_size:
      return False

    with self._storage_file.open('a', encoding='utf-8') as output_stream:
      output_stream.write(entry)
    return True

  def get(self, key: str) -> list[str]:
    """Retrieve all values with corresponding key.

    Args:
      key: The target key used to match pairs.

    Returns:
      A list of values where their key matches the target key.
    """
    result = []
    with self._storage_file.open(encoding='utf-8') as input_stream:
      for line in input_stream:
        # Remove trailing newline so it won't become part of the value.
        entry_key, entry_value = line.rstrip().split(':', 1)
        if entry_key == key:
          result.append(entry_value)
    return result


class DatabaseCLI:
  """A simple CLI wrapping around the database API.

  This CLI also comes with an authorization mechanism so we'd be able to keep
  secrets in the database.
  """

  SECRET_PREFIX = 'secret_'
  PASSWORD_KEY = f'{SECRET_PREFIX}password'

  ADD_REQUEST_REGEX = re.compile(r'^add (?P<key>[^ ]+) (?P<value>[^ ]+)$')
  GET_REQUEST_REGEX = re.compile(r'^get (?P<key>[^ ]+)$')
  AUTH_REQUEST_REGEX = re.compile(r'^auth (?P<password>[^ ]+) (?P<request>.+)$')

  def __init__(self, database: TextDatabase):
    """Construct a DatabaseCLI for a given database.

    Args:
      database: The database to work upon.
    """
    self._database = database

  def serve(
      self,
      input_stream: io.TextIOBase,
      output_stream: io.TextIOBase,
  ) -> None:
    """Read and handle requests from a stream until depleted.

    Each request and response should be in their own line and all the traffic
    except the new line should be encoded as hex string. The decision is made to
    prevent any escaping issue in the transmission channel.

    Args:
      input_stream: Stream to read request from.
      output_stream: Stream to write response to.
    """
    while request := input_stream.readline():
      request = bytes.fromhex(request).decode('utf-8')
      response = self._handle_request(request)
      response = response.encode('utf-8').hex()
      output_stream.write(f'{response}\n')
      output_stream.flush()

  def _handle_request(self, request: str, *, authorized: bool = False) -> str:
    """Handle a request from the user.

    Args:
      request: A string represending the request, should be matching the format
        of one of recognized request.
      authorized: Whether we are granted permission to execute privileged
        operations.

    Return:
      A string indicating the execution result, prefixed by a 'ok' or 'fail'.
    """
    # Add request?
    if match := self.ADD_REQUEST_REGEX.match(request):
      permitted = authorized or not match['key'].startswith(self.SECRET_PREFIX)
      result = permitted and self._database.add(match['key'], match['value'])
      return 'ok: add' if result else 'fail: add failed'
    # Get request?
    if match := self.GET_REQUEST_REGEX.match(request):
      permitted = authorized or not match['key'].startswith(self.SECRET_PREFIX)
      result = permitted and self._database.get(match['key'])
      return f'ok: get: {result}' if result else 'fail: get failed'
    # Auth request?
    if match := self.AUTH_REQUEST_REGEX.match(request):
      authorized = authorized or self._validate_password(match['password'])
      return self._handle_request(match['request'], authorized=authorized)
    # Unknown request.
    return 'fail: unknown request'

  def _validate_password(self, password: str) -> bool:
    """Validate whether the given password matches the one in database.

    In case there's no password stored in the database, the validation will
    always pass.

    Args:
      password: The password the validate.

    Returns:
      A boolean indicating whether the password matches.
    """
    password_history = self._database.get(self.PASSWORD_KEY)
    if not password_history:
      return True
    return hmac.compare_digest(password, password_history[-1])


def challenge() -> None:
  """Start the challenge!"""

  flag = pathlib.Path('flag').read_text(encoding='utf-8').strip()
  assert re.match('^CTF{[0-9a-zA-Z_@!?-]+}$', flag)

  with tempfile.NamedTemporaryFile(prefix='py-storage-') as storage:
    database = TextDatabase(pathlib.Path(storage.name), 10240)
    password = secrets.token_hex(16)
    database.add(DatabaseCLI.PASSWORD_KEY, password)
    database.add(f'{DatabaseCLI.SECRET_PREFIX}flag', flag)
    DatabaseCLI(database).serve(sys.stdin, sys.stdout)


if __name__ == '__main__':
  challenge()
