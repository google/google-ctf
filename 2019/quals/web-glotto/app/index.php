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

    require_once('config.php');
    require_once('watchdog.php');

    function gen_winner($count, $charset='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    {
        $len = strlen($charset);
        $rand = openssl_random_pseudo_bytes($count);
        $secret = '';

        for ($i = 0; $i < $count; $i++)
        {
            $secret .= $charset[ord($rand[$i]) % $len];
        }
        return $secret;
    }

    if (isset($_GET['src'])) {
        die(highlight_string(file_get_contents(__FILE__)));
    } else if (isset($_POST['code'])) {
        session_start();
        if (!isset($_SESSION['winner'])) die;
        $win = $_SESSION['winner'];
        unset($_SESSION['winner']);
        session_destroy();


        if ($_POST['code'] === $win)
        {
            die("You won! $flag");
        } else {
            sleep(5);
            die("You didn't win :(<br>The winning ticket was $win");
        }
    }


    session_start();

    $tables = array(
        'march',
        'april',
        'may',
        'june',
    );

    $winner = gen_winner(12);
    $_SESSION['winner'] = $winner;

    $db = new mysqli(null, $dbuser, $dbpass, $dbname, null, $socket);
    //$db = new mysqli($dbhost, $dbuser, $dbpass, $dbname);
    
    if ($db->connect_errno) {
        printf("Connect failed: %s\n", $db->connect_error);
        exit();
    }   

    $db->query("SET @lotto = '$winner'");


    for ($i = 0; $i < count($tables); $i++)
    {
        $order = isset($_GET["order{$i}"]) ? $_GET["order{$i}"] : '';
        if (stripos($order, 'benchmark') !== false) die;
        ${"result$i"} = $db->query("SELECT * FROM {$tables[$i]} " . ($order != '' ? "ORDER BY `".$db->escape_string($order)."`" : ""));
        if (!${"result$i"}) die;
    }
?>
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <!-- The above 3 meta tags *must* come first in the head; any other head content must come *after* these tags -->
    <title>Win The Lotto!</title>

    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap.min.css" rel="stylesheet">

    <style>
        .cap {
            text-transform: capitalize;
        }
    </style>


  </head>
  <body>
    <nav class="navbar navbar-inverse navbar-fixed-top">
      <div class="container">
        <div class="navbar-header">
          <a class="navbar-brand" href="/">gLotto</a>
        </div>
        <div class="navbar-right">
            <button type="submit" class="btn btn-primary" data-toggle="modal" data-target="#myModal">Check your ticket!</button>
        </div>
      </div>
    </nav>

    <!-- Main jumbotron for a primary marketing message or call to action -->
    <div class="jumbotron">
      <div class="container">
        <h1>Welcome!</h1>
        <p>Here are the results of past lottery draws, good luck!</p>
      </div>
    </div>

    <div class="container">
      <div class="row">
      <?php for ($i = 0; $i < count($tables); $i++): ?>
        <div class="col-md-4">
            <div class="panel panel-default">
              <div class="panel-heading cap"><?=$tables[$i]?></div>
                  <table class="table">
                      <tr><th><a href="?order<?=$i?>=date">Date</a></th><th><a href="?order<?=$i?>=winner">Winning ticket</a></th></tr>
                            <?php
                                while ($row = ${"result$i"}->fetch_array())
                                {
                                    echo '<tr>';
                                    echo "<td>{$row[0]}</td><td>{$row[1]}</td>";
                                    echo '</tr>';
                                }
                                echo "\n";
                            ?>
                </table>
            </div>
        </div>

      <?php endfor; ?>
      </div>

        <!-- Modal -->
        <div class="modal fade" id="myModal" tabindex="-1" role="dialog" aria-labelledby="myModalLabel">
          <div class="modal-dialog" role="document">
            <div class="modal-content">
                <form action="" method="POST">
                  <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                    <h4 class="modal-title" id="myModalLabel">Check your ticket</h4>
                  </div>
                  <div class="modal-body">
                      <div class="input-group">
                        <span class="input-group-addon" id="sizing-addon2">Code</span>
                        <input type="text" class="form-control" name="code" id="code">
                      </div>
                  </div>
                  <div class="modal-footer">
                    <button type="submit" class="btn btn-default">Submit</button>
                  </div>
                </form>
            </div>
          </div>
        </div>

      <hr>

      <footer>
        <a href="?src">Sauce</a>
      </footer>

    </div> <!-- /container -->

    <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.3/jquery.min.js"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js"></script>

  </body>
</html>
