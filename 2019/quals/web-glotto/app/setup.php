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

    //$db = new mysqli(null, 'root', $rootpasswd, '', null, $socket);
    $db = new mysqli($dbhost, 'root', $rootpasswd, '', null);
    
    if ($db->connect_errno) {
        printf("Connect failed: %s\n", $db->connect_error);
        exit();
    }    
    
    if (!$db->query("CREATE USER '$dbuser'@'%' IDENTIFIED BY '$dbpass';"))
        echo $db->error."\n";
    if (!$db->query("GRANT ALL ON $dbname.* TO '$dbuser'@'%';"))
        echo $db->error."\n";
    if (!$db->query("CREATE DATABASE $dbname;"))
        echo $db->error."\n"; 

    $db->select_db($dbname);
    $result = $db->multi_query(file_get_contents('db.sql'));
    if (!$result) echo $db->error."\n";

