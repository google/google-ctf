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

class Debug {
    #username;
    constructor(username="") {
        this.#username = username
    }
    toString() {
        return `debug_${this.#username}`
    }
}

// Extend user object
function load_debug(user) {
    let debug;
    try {
        debug = JSON.parse(window.name);
    } catch (e) {
        return;
    }

    if (debug instanceof Object) {
        user.debug = new Debug(user.username);
        Object.assign(user.debug, debug);
    }

    if(user.debug.debugUser){
        user.toString = () => user.debug.toString();
    }
    
    if(user.debug.verbose){
        console.log(user);
        console.log(user.debug);
    }

    if(user.debug.showAll){
        document.querySelectorAll('*').forEach(e=>e.classList.add('display-block'));
    }

    if(user.debug.keepDebug){
        document.querySelectorAll('a').forEach(e=>e.href=append_debug(e.href));
    }else{
        document.querySelectorAll('a').forEach(e=>e.href=remove_debug(e.href));
    }

    window.onerror = e =>alert(e);
}

function append_debug(u){
    const url = new URL(u);
    url.searchParams.append('__debug__', 1);
    return url.href;
}

function remove_debug(u){
    const url = new URL(u);
    url.searchParams.delete('__debug__');
    return url.href;
}