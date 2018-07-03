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

    function login($user, $password) {
        $u = get_user($user);

        if (!$u or sha1($password) !== $u['password']) {
            error('Wrong login.');
        }

        $_SESSION['user'] = $u;

        return true;
    }

    if (isset($_SESSION['u'])) {
        header('Location: /bbs');
        exit;
    }

    if (isset($_POST['submit'])) {
        if (login((string)$_POST['username'], (string)$_POST['password'])) {
            header('Location: /');
            exit;
        }
    }

?>
      <form class="form-signin" method="POST">
        <h2 class="form-signin-heading">Please sign in</h2>
        <input type="text" name="username" class="input-block-level" placeholder="Username">
        <input type="password" name="password" class="input-block-level" placeholder="Password">
        <button class="btn btn-large btn-primary" name="submit" type="submit">Sign in</button>
      </form>
