<?php
// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
ini_set('display_errors', 1);
error_reporting(E_ALL);

include 'flag.php'; //defines $flag

class B {
  function __destruct() {
    global $flag;
    echo $flag;
  }
}

if (isset($_POST['p'])) {
    ob_start();
    $a = unserialize($_POST['p']);
    if ($a === False) {
        ob_end_clean();
    }
    throw new Exception('Something tragic happened, maybe phpggc can help?');
} else {
	echo highlight_file(__FILE__);
}
