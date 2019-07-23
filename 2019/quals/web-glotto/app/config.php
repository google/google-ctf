<?php
// Copyright 2019 Google LLC
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

    $flag = 'CTF{3c2ca0d10a5d4bf44bc716d669e074b2}';

    $dbuser = 'glotto';
    $dbpass = '';
    $dbname = 'glotto';    
    $rootpasswd = '';
    
    $socket = "/cloudsql/ctf-web-kuqo48d:europe-west1:glotto";


    ini_set('display_errors', 0);    
