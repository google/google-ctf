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
    use Google\Cloud\Datastore\DatastoreClient;

    $datastore = new DatastoreClient([
        'projectId' => $PROJECT,
        'namespaceId' => 'bbs'
    ]);


    function get_user($username) {
        global $datastore;

        if (empty($username))
            return;

        $key = $datastore->key('user', $username);
        $entity = $datastore->lookup($key);

        if (!is_null($entity)) {
            return $entity;
        }
    }

    function create_user($username, $password, $admin=false) {
        global $datastore;

        if (empty($username))
            return;

        $key = $datastore->key('user', $username);

        $entity = $datastore->entity($key, [
            'username' => $username,
            'password' => $password,
            'admin' => $admin
        ]);
        $datastore->insert($entity);
    }


    function create_post($title, $content, $username) {
        global $datastore;

        $key = $datastore->key('post');
        $entity = $datastore->entity($key, [
            'title' => $title,
            'content' => $content,
            'username' => $username,
            'ts' => time()
        ]);
        $datastore->insert($entity);
    }

    function get_post($id) {
        global $datastore;

        $key = $datastore->key('post', (string)$id);
        $entity = $datastore->lookup($key);

        if (!is_null($entity)) {
            return $entity;
        }
    }

    function get_posts($user) {
        global $datastore;

        $query = $datastore->query()
            ->kind('post')
            ->filter('username', '=', 'admin')
            ->order('ts', 'DESCENDING');

        $result = [];

        foreach ($datastore->runQuery($query) as $p)
            $result[] = $p;

        $query = $datastore->query()
            ->kind('post')
            ->filter('username', '=', $user)
            ->order('ts', 'DESCENDING');

        foreach ($datastore->runQuery($query) as $p)
            $result[] = $p;

        return $result;
    }

    function init() {
        global $FLAG;

        if (!get_user('admin')) {
            create_user('admin', hmac($FLAG), true);
            create_post('Welcome', 'W3Lc0me tO tHE c00l3st bbs ev4r!', 'admin');
        }
    };

    init();
