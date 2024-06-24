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

module.exports = {
  head_start : `
  <html>
  <head>
    <link rel="stylesheet" href="../css/stylesheet.css">
    <title> ♡♡ GRAND PRIX HEAVEN ♡♡ </title>
  `,
  csp : `
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self' https://cdn.jsdelivr.net/npm/exifreader@4.22.1/dist/exif-reader.min.js; connect-src 'self'; style-src 'self'; font-src 'self'; img-src 'self';">
  `,
  head_end : `
  </head>
  `,
  index : `
  <body>
  <h1>☆ WELCOME ☆</h1>
  <img src="../image/racergirl.png" width="50%" height="100%"></img>
  <p> Are you a fan of F1 racing? Share with us your dream cars! </p>
  <ol>
  <!--https://codepen.io/antoniasymeonidou-->
  <li><a class="arrow" href="/fave"><i class="fas fa-arrow-alt-right"></i>FAVES</a></li>
  <li><a class="arrow" href="new-fave"><i class="fas fa-arrow-alt-right"></i>NEW FAVE</a></li>
  </ol>
  </body>
  </html>
  `,
  faves : `
  <body>
    <h1> ☆ FAVES ☆ </h1>
    <h2 id="title-card"></h2>
    <div id="desc-card"></div>
    <div id="date-card"></div>
    <img id="img-card">
  `,
  retrieve: `
  <script src="../js/retrieve.js"></script>
  `,
  mediaparser :  `
  <script src="https://cdn.jsdelivr.net/npm/exifreader@4.22.1/dist/exif-reader.min.js"></script>
  <script src="../js/mediaparser.js"></script>
  `,
  apiparser: `
  <script src="../js/apiparser.js"></script>
  `,
  upload_form: `
  <div class="car-box">
  <h2>NEW CAR</h2>
  <form method="post" enctype="multipart/form-data" action="/api/new-car">
    <div class="user-box">
      <label for="year">YEAR CAR WAS MANUFACTURED</label><br><br>
      <input name="year" id="year" value="2004" />
    </div>
    <div class="user-box">
      <label for="make">MAKE OF THE CAR</label><br><br>
      <input name="make" id="make" value="Ferrari" />
    </div>
    <div class="user-box">
      <label for="model">MODEL OF THE CAR</label><br><br>
      <input name="model" id="model" value="F2004" />
    </div>
    <div class="user-box">
      <label for="image">Image</label><br><br>
      <input id="image" name="image" type="file" />
    </div>
    <div>
      <button>Vroom Vroom</button>
    </div>
  </form>
</div>
  `,
  footer: `
  </body>
  </html>
  `
};
