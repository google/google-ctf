#!/usr/bin/env python3
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

import requests
import json

# What should URL be?
def check(url="http://127.0.0.1:3000/submit_kernel"):
    test_kernel = """\
def player_kernel(mapdata_ref, auxdata_ref, out_ref):
    phase = auxdata_ref[0]
    step = auxdata_ref[1]
    @pl.when(phase == 0)
    def _():
        out_ref.at[1].set(1)
        out_ref.at[2].set(0)
    xstart = 3
    out_ref.at[xstart + 0].set(16) 
    out_ref.at[xstart + 1].set(1)
    out_ref.at[xstart + 2].set(4)
    out_ref.at[xstart + 3].set(32)
    out_ref.at[xstart + 4].set(1)
    out_ref.at[xstart + 5].set(3)
    out_ref.at[xstart + 6].set(80)
    out_ref.at[xstart + 7].set(2)
    out_ref.at[xstart + 8].set(3)
    act = auxdata_ref[3 * phase + (step % 2)]
    is_maxstep = (step + 1) > auxdata_ref[3*phase - 1]
    phase = lax.cond(is_maxstep, lambda x, _: x, lambda _, y: y, phase + 1, phase)
    step = lax.cond(is_maxstep, lambda x, _: x, lambda _, y: y, 0, step + 1)
    out_ref.at[1].set(phase)
    out_ref.at[2].set(step)
    out_ref.at[0].set(act)\
"""

    try:
        response = requests.post(url, data={'kernel_input': test_kernel})
        response.raise_for_status()  # Raise an exception for HTTP errors (4xx or 5xx)

        response_data = response.json()

        if response_data.get('status') == 'success':
            if 'gametrace' in response_data and 'mapn' in response_data['gametrace']:
                flag = response_data['gametrace'].get('flag')
                if flag == "CTF{1r0nw00d_h43_4ll_tH3_fl0pS_ar3_y0u_r3AdY4aGi}":
                    return True, ""
                else:
                    return False, "Invalid flag"
            else:
                print(f"Health check failed: 'gametrace' or 'mapn' missing in response. Response: {response_data}")
                return False, "Invalid response structure."
        else:
            print(f"Health check failed: Server returned an error status. Response: {response_data}")
            return False, f"Server returned an error: {response_data.get('message', 'No message provided')}"

    except requests.exceptions.ConnectionError:
        print(f"Health check failed: Could not connect to the server at {url}. Is the Flask app running?")
        return False, "Connection error."
    except requests.exceptions.Timeout:
        print(f"Health check failed: Request timed out for {url}.")
        return False, "Request timeout."
    except requests.exceptions.RequestException as e:
        print(f"Health check failed: An unexpected request error occurred: {e}")
        return False, f"Request error: {e}"
    except json.JSONDecodeError:
        print(f"Health check failed: Could not decode JSON response from {url}. Response content: {response.text}")
        return False, "Invalid JSON response."

if __name__ == "__main__":
    # Ensure your Flask app is running on ?
    is_healthy, message = check()
    print(f"\nHealth Check Result: {'PASS' if is_healthy else 'FAIL'}")
    print(f"Message: {message}")
    exit(0 if is_healthy else 1)
