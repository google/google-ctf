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

import "./untrusted_content.js";

const shareButton = document.getElementById("share-with-admin");

async function share(recaptchaToken) {
  const body = document.querySelector("untrusted-content").html;
  const resp = await fetch(
    `/share-with-admin?body=${encodeURIComponent(body)}&recaptcha=${encodeURIComponent(recaptchaToken)}`
  );
  if (resp.status === 200) {
    alert("Admin shall see the message very soon");
  } else {
    alert("Something went wrong!");
  }
}

function recaptcha() {
  grecaptcha.ready(function() {
    grecaptcha.execute(window.RECAPTCHA_SITE_KEY, {action: 'submit'}).then(function(token) {
      share(token);
    });
  });
}

shareButton.addEventListener("click", () => recaptcha());
