/**
 * Copyright 2024 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

class Requester {
    constructor(url) {
        const clean = (path) => {
          try {
            if (!path) throw new Error("no path");
            let re = new RegExp(/^[A-z0-9\s_-]+$/i);
            if (re.test(path)) {
              // normalize
              let cleaned = path.replaceAll(/\s/g, "");
              return cleaned;
            } else {
              throw new Error("regex fail");
            }
          } catch (e) {
            console.log(e);
            return "dfv";
          }
          };
        url = clean(url);
        this.url = new URL(url, 'https://grandprixheaven-web.2024.ctfcompetition.com/api/get-car/');
      }
    makeRequest() {
        return fetch(this.url).then((resp) => {
            if (!resp.ok){
                throw new Error('Error occurred when attempting to retrieve media data');
            }
            return resp;
        });
    }
  }
