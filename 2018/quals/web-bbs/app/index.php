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
    define('MAIN', 1);
    require_once('config.php');

    session_start();
    ob_start();

    $logged_in = isset($_SESSION['user']);


    switch($_SERVER["REQUEST_URI"]) {
        case "/login":
            $page = "login.php";
            break;
        case "/register":
            $page = "register.php";
            break;
        case "/profile":
            $page = "profile.php";
            break;
        case "/error":
            $page = "error.php";
            break;
        case "/report":
            $page = "report.php";
            break;
        case "/logout":
            $logged_in = false;
            session_destroy();
            $page = "home.php";
            break;
        case "/home":
        default:
            if ($logged_in)
                $page = "bbs.php";
            else
                $page = "home.php";
            break;
    }



?>
<?php include('header.php');?>
    <div class="container">

    <?php include($page); ?>

    </div> <!-- /container -->

<?php include('footer.php');?>

