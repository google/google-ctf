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

addEventListener("load", (event) => {
  params = new URLSearchParams(window.location.search);
  let requester = new Requester(params.get('F1'));
  try {
    let result = requester.makeRequest();
    result.then((resp) => {
        if (resp.headers.get('content-type') == 'image/jpeg') {
          var titleElem = document.getElementById("title-card");
          var dateElem = document.getElementById("date-card");
          var descElem = document.getElementById("desc-card");
          
          resp.arrayBuffer().then((imgBuf) => {
              const tags = ExifReader.load(imgBuf);
              descElem.innerHTML = tags['ImageDescription'].description;
              titleElem.innerHTML = tags['UserComment'].description;
              dateElem.innerHTML = tags['ICC Profile Date'].description;
          })
        }
    })
  } catch (e) {
    console.log("an error occurred with the Requester class.");
  }
});
