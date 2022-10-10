# Copyright 2022 Google LLC
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

"""Defines the environment for the server. This file differs on the client."""

import utils

environ = "server"

"""Returns the current game instance."""
game = None

# Decorators.
def server_only(f):
	"""The decorated function exists only on the server."""
	return f

def server_only_or(server_val):
	"""On the server, call the decorated function; on the client, return server_val."""
	return client_only

def client_only(f):
	"""The decorated function exists only on the client."""
	def raise_error(*args, **kwargs):
		raise RuntimeError(f"Function {f} is client-only.")
	return raise_error

def client_only_or(server_val):
	"""On the client, call the decorated function; on the server, return server_val."""
	def wrapper(f):
		def return_server_val(*args, **kwargs):
			return server_val
		return return_server_val
	return wrapper

def pick(*, client, server):
	"""On the client, return client. On the server, return server."""
	return server
