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

const sleep = (d) => new Promise((r) => setTimeout(r, d));

async function appendFileInfo(id) {
  const ul = document.querySelector("#filesList");
  const row = document.createElement("a");
  row.className = "list-group-item list-group-item-action";
  row.href = "#" + id;
  row.id = "file-" + id;
  row.innerText = GAMES[id].name;
  ul.appendChild(row);
}

async function previewFile(body, metadata) {
  console.log(metadata);
  await window.safeFrameRender(body, "text/html;charset=utf-8", metadata);
}
