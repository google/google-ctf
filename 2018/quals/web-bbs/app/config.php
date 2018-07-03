<?php
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


error_reporting(E_ALL | E_STRICT);
?>
<?php
    require __DIR__ . '/vendor/autoload.php';
    require_once('lib.php');


    $HMAC_KEY = 'totallyrandomkeyIswear';
    $PROJECT = getenv('GOOGLE_CLOUD_PROJECT') ?: 'ctf-web-kuqo48d';
    $BUCKET = getenv('GOOGLE_STORAGE_BUCKET') ?: 'ctf-bbs';

    //error_reporting(E_ALL);
    ini_set('display_errors', '0');

?>
