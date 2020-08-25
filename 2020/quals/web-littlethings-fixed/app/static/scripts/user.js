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

class User {
    #username; #theme; #img
    constructor(username, img, theme) {
        this.#username = username
        this.#theme = theme
        this.#img = img
    }
    get username() {
        return this.#username
    }

    get img() {
        return this.#img
    }

    get theme() {
        return this.#theme
    }

    toString() {
        return `user_${this.#username}`
    }
}

function make_user_object(obj) {

    const user = new User(obj.username, obj.img, obj.theme);
    window.load_debug?.(user);

    // make sure to not override anything
    if (!is_undefined(document[user.toString()])) {
        return false;
    }
    document.getElementById('profile-picture').src=user.img;
    window.USERNAME = user.toString();
    document[window.USERNAME] = user;
    update_theme();
}
