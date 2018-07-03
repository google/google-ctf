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

    use Google\Cloud\Storage\StorageClient;


    function hmac($data) {
        global $HMAC_KEY;
        return hash_hmac('sha256', $data, $HMAC_KEY);
    }

    function error($msg) {
        $_SESSION['error'] = $msg;
        header('Location: /error');
        exit;
    }

    function gcs_write($path, $data) {
        global $PROJECT, $BUCKET, $KEYFILE;

        $storage = new StorageClient([
            'projectId' => $PROJECT
        ]);

        $storage->bucket($BUCKET)->upload($data, [
            'name' => $path,
        ]);
    }

    function gcs_read($path, $opts) {
        global $PROJECT, $BUCKET, $KEYFILE;

        $storage = new StorageClient([
            'projectId' => $PROJECT
        ]);

        $bucket = $storage->bucket($BUCKET);
        $object = $bucket->object($path);

        if ($object->exists())
            return $object->downloadAsString($opts);
    }

    function dbg($s) {
        error_log(var_export($s,true), 4);
    }

    function leet($str) {
        $l = function ($c) {
            $tl = ['a' => '4', 'e' => '3', 'l' => '1', 'o' => '0', 's' => '5', 't' => '7', ];
            if (array_key_exists($c, $tl) && rand(0, 99) < 50)
                $c = $tl[$c];

            if (rand(0, 99) < 50)
                $c = strtoupper($c);

            return $c;
        };

        $s = str_split($str);
        $s = array_map($l, $s);
        return implode($s);
    }
