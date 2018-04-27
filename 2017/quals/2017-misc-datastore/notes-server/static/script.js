// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.



window.onload = function() {
    $_ = document.querySelector.bind(document)
    $_('#register').onclick = function() {
        var uname = $_('#username').value
        var hexed = uname.split("")
            .map( function(e) {
                return e.charCodeAt(0).toString(16)
            })
            .join("")
        var XHR = new XMLHttpRequest()
        XHR.open("POST", "/register")
        XHR.setRequestHeader("Content-Type", "application/x-www-formurlencoded")
        XHR.withCredentials = true
        XHR.onload = function() {
            if (XHR.status == 200) {
                $_('.user-create').innerText = "Your access token is " + XHR.response
            } else {
                $_('.user-create').innerText = "Error: " + XHR.response
            }
        }
        XHR.send("username="+hexed)
    }
}
 