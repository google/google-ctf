/**
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

function set_dark_theme(obj) {
    const theme_url = "/static/styles/bootstrap_dark.css";
    document.querySelector('#bootstrap-link').href = theme_url;
    localStorage['theme'] = theme_url;
}

function set_light_theme(obj) {
    theme_url = "/static/styles/bootstrap.css";
    document.querySelector('#bootstrap-link').href = theme_url;
    localStorage['theme'] = theme_url;
}

function update_theme() {
    const theme = document[USERNAME].theme;
    const s = document.createElement('script');
    s.src = `/theme?cb=${theme.cb}`;
    document.head.appendChild(s);
}

document.querySelector('#bootstrap-link').href = localStorage['theme'];