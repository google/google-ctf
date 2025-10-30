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

from flask import Flask, render_template, request, jsonify
from contextlib import contextmanager
import tempfile
import subprocess
import json
import tempfile
import logging
from waitress import serve


app = Flask(__name__)
app.logger.setLevel(logging.INFO)


def process_kernel(kernel_text):
    app.logger.info('Received kernel text:\n%s', kernel_text)

    if not kernel_text.startswith('def player_kernel(mapdata_ref, auxdata_ref, out_ref):\n'):
        raise ValueError('invalid kernel signature')

    if not all(map(lambda l: l == '' or l.startswith(' '*4), kernel_text.splitlines()[1:])):
        raise ValueError('invalid indentation')

    try:
        with open("kernel.py", "r") as f:
            kernel = f.read().replace('# INSERT USER CODE HERE', kernel_text)

        app.logger.info('After template expansion:\n%s', kernel)
        with tempfile.NamedTemporaryFile(suffix="_kernel.py", mode="w") as f:
            f.write(kernel)
            f.flush()

            args = [
                "nsjail",
                "-Mo",
                "--user",
                "99999",
                "--group",
                "99999",
                "-R",
                "/bin/",
                "-R",
                "/lib/",
                "-R",
                "/lib64/",
                "-R",
                "/usr/",
                "-R",
                f.name,
                "-R",
                "/venv",
                "--disable_clone_newpid",
                "--disable_proc",
                "--",
                "/venv/bin/python3",
                f.name
            ]
            compiled = subprocess.check_output(
                args,
                timeout=10,
                stderr=subprocess.PIPE,
            )

        output = subprocess.check_output(
            ["/venv/bin/python3", "game.py"],
            input=compiled,
        )
        trace = json.loads(output.decode())
        app.logger.info("mapn: %s", trace['mapn'])

        return {"status": "success", "message": "game.py executed successfully.", "gametrace":  trace}
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        app.logger.exception('error executing command: %s %s', e.stdout, e.stderr)
        return {"status": "error", "message": "Error executing game.py"}
    except Exception as e:
        app.logger.exception(e)
        return {"status": "error", "message": f"An unexpected error occurred."}


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/submit_kernel', methods=['POST'])
def submit_kernel():
    if request.method == 'POST':
        kernel_text = request.form['kernel_input']
        result = process_kernel(kernel_text)
        return jsonify(result)


if __name__ == '__main__':
    serve(app, host='127.0.0.1', port=3000)
