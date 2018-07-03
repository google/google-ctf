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
    require_once('db.php');
    require_once('lib.php');

    session_start();
    ob_start();

    header('X-Frame-Options: SAMEORIGIN');
    header("Content-Security-Policy: default-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; ");

    $logged_in = isset($_SESSION['user']);

    function action_posts() {
        global $logged_in;

        if ($logged_in) {
            $posts = get_posts($_SESSION['user']['username']);

            foreach($posts as $p):
                $id = $p->key()->pathEndIdentifier();
            ?>
            <a id="<?=$id?>"></a>
            <div class="page-header" onclick="bbs.quote('<?=$id?>')">
                <h2><span class="no">#<?=$id?></span><?=htmlentities($p['title'])?><span class="username"><?=htmlentities($p['username'])?></span></h2>
            </div>
            <p class="post_content"><?=nl2br(htmlentities(leet($p['content'])))?></p>
            <div class="report"><a href="#" onclick="bbs.report('<?=$id?>')">Report</a></div>
            <?php endforeach; ?><?

            $contents = ob_get_clean();
            echo base64_encode($contents);
        }
    }

    function action_post($id) {
        global $logged_in;

        if ($logged_in) {
            $post = get_post($id);

            if ($post && in_array($post['username'], ['admin', $_SESSION['user']['username']])) {
                $contents = nl2br(htmlentities($post['content']));
                echo base64_encode($contents);
            } else {
                echo base64_encode('Private post.');
            }
        }
    }

    $p = explode('/', $_SERVER["REQUEST_URI"]);
    $action = $p[2];
    $arg = @$p[3];

    switch ($action) {
        case 'posts':
            action_posts();
            break;
        case 'post':
            action_post($arg);
            break;
        default:
            break;
    }
