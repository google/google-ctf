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

    function watchdog()
    {
        global $rootpasswd, $socket, $dbuser, $dbhost;

        $db = new mysqli(null, 'root', $rootpasswd, '', null, $socket);
        //$db = new mysqli($dbhost, 'root', $rootpasswd, '', null);
        $result = $db->query('show processlist');
        while ($row = $result->fetch_array())
        {
            if ($row['User'] === $dbuser && intval($row['Time']) > 5)
            {
                //echo "Killing {$row['Id']} ({$row['Time']})\n";
                $db->query('KILL '.$row['Id']);
            }
        }
    }

    watchdog();
