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

    if (!defined('MAIN')) die;


    if (isset($_POST['submit'])) {
        create_post((string)$_POST['title'], (string)$_POST['content'], $_SESSION['user']['username']);
    }

    $posts = get_posts($_SESSION['user']['username']);

?>
<div id="bbs">

</div>
<form class="form-signin" method="POST">
    <h2>New post</h2>
    <input type="text" name="title" class="input-block-level" placeholder="Title">
    <textarea name="content" rows="6" id="post_txt"></textarea>
    <button class="btn btn-large btn-primary" name="submit" type="submit">Post</button>
</form>
