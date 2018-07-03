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

    require_once('config.php');

    use google\appengine\api\taskqueue\PushTask;


    if (!defined('MAIN')) die;

    if (isset($_REQUEST['post'])) {
        if (strpos((string)$_REQUEST['post'], '/admin/') !== 0) {
            die('Invalid post');
        }

        $url = "https://{$_SERVER['HTTP_HOST']}".$_REQUEST['post'];

        $task = new PushTask(
            '/submit',
            ['url' => $url, 'service' => 'bbs']
        );
        $task_name = $task->add('xss');
    }
?>
<p>The post has been reported. The admin will take a look shortly.</p>
