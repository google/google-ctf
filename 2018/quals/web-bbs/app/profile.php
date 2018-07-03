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

    function update($arr) {
        global $datastore;

        $update = array();
        $u = get_user($_SESSION['user']['username']);

        if (!empty($arr['password'])) {
            // Don't do this at home kids!
            $u['password'] = sha1((string)$arr['password']);
        }

        if (!empty($arr['website'])) {
            $u['website'] = (string) $arr['website'];
        }

        if (!empty($_FILES["avatar"]["tmp_name"])) {
            $path = $_FILES["avatar"]["tmp_name"];
            if (!$im = imagecreatefrompng($path)) {
                die("I don't like that image.");
            }

            list($width, $height) = getimagesize($path);

            $resized = imagecreatetruecolor(64, 64);
            imagecopyresized($resized, $im, 0, 0, 0, 0, 64, 64, $width, $height);

            ob_start();
            imagepng($resized);
            $resized = ob_get_clean();

            $h = md5($resized);

            $p = 'avatar/'.$h;
            $u['avatar'] = $p;
            gcs_write($p, $resized);
        }

        $datastore->update($u);
        $_SESSION['user'] = $u;
    }

    if (!$logged_in) {
        header('Location: /');
        exit;
    }


    if (isset($_POST['submit'])) {
        update($_POST);
        header('Location: /profile');
        exit;
    }

?>
      <form class="form-signin" method="POST" enctype="multipart/form-data">
        <?php if ($_SESSION['user']['avatar']): ?>
        <img class="p_avatar" src="/<?=$_SESSION['user']['avatar']?>">
        <?php endif; ?>
        <h2 class="form-signin-heading">Profile</h2>
        <p><?=htmlentities($_SESSION['user']['username'])?></p>
        <input type="password" name="password" class="input-block-level" placeholder="Password">
        <input type="password" name="password2" class="input-block-level" placeholder="Repeat assword">
        <input type="text" name="website" class="input-block-level" placeholder="Website" value=<?=htmlentities($_SESSION['user']['website'])?>>
        <label for="avatar">Avatar</label> <input type="file" name="avatar" id="avatar" placeholder="Avatar"><br><br>

        <button class="btn btn-large btn-primary" name="submit" type="submit">Update</button>
      </form>
