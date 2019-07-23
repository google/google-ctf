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
error_reporting( E_ALL );

session_start();

// totally not copy&pasted from somewhere...
function get_size($file, $mime_type) {
    if ($mime_type == "image/png"||$mime_type == "image/jpeg") {
        $stats = getimagesize($file);
        $width = $stats[0];
        $height = $stats[1];
    } else {
        $xmlfile = file_get_contents($file);
        $dom = new DOMDocument();
        $dom->loadXML($xmlfile, LIBXML_NOENT | LIBXML_DTDLOAD);
        $svg = simplexml_import_dom($dom);
        $attrs = $svg->attributes();
        $width = (int) $attrs->width;
        $height = (int) $attrs->height;
    }
    return [$width, $height];
}

function workdir() {
    $d = 'upload/'.md5(session_id());

    if (!is_dir($d))
        mkdir($d);
    return $d;
}

function list_photos() {
    $d = 'upload/'.md5(session_id());

   if (!is_dir($d)) return [];

    $result = [];

    foreach(glob("{$d}/*.*") as $f) {
        if (strrpos($f, 'small') === FALSE)
            $result[basename($f)] = $f;
    }
    return $result;
}

function upload() {
    if (!isset($_FILES['photo']))
        return;

    $p = new PhotoUpload($_FILES['photo']['tmp_name']);
    $p->thumbnail();
}

class PhotoUpload {
    private $failed = false;

    function __construct($path) {
        $formats = [
            "image/gif" => "gif",
            "image/png" => "png",
            "image/jpeg" => "jpg",
            "image/svg+xml" => "svg",
            // Uncomment when launching gVideoz
            //"video/mp4" => "mp4",
        ];

        $mime_type = mime_content_type($path);

        if (!array_key_exists($mime_type, $formats)) {
            die;
        }

        $size = get_size($path, $mime_type);
        if ($size[0] * $size[1] > 65536) {
            die;
        }

        $this->ext = $formats[$mime_type];
        $this->name = hash_hmac('md5', uniqid(), $secret).".{$this->ext}";

        move_uploaded_file($path, workdir()."/{$this->name}");
    }

    function thumbnail() {
         exec(escapeshellcmd('convert '.workdir()."/{$this->name}".' -resize 128x128 '.workdir()."/{$this->name}_small.jpg"), $out, $ret);
         if ($ret)
            $this->failed = true;
    }

    function __destruct() {
        if ($this->failed) {
            shell_exec(escapeshellcmd('rm '.workdir()."/{$this->name}"));
        }
    }
}

if (isset($_GET['action'])) {
    switch ($_GET['action']) {
        case 'upload':
            upload();
            header('Location: ?');
            die;
            break;
        case 'src':
            show_source(__FILE__);
            die;
        default:
            break;
    }
}

?>
<html>
    <head>
        <title>gPhotoz</title>
    </head>
    <body>
        <div>
            <form action="?action=upload" method="POST" enctype="multipart/form-data">
                <input type="file" name="photo"><input type="submit" value="Upload">
            </form>
        </div>
        <div>
            <?php foreach(list_photos() as $name => $path): ?>
            <div>
                <a href="<?=$path?>" alt="<?=$name?>"><img src="<?=$path.'_small.jpg'?>"></a>
            </div>
            <?php endforeach ?>
        </div>
    </body>

    <a href="?action=src"></a>
</html>
