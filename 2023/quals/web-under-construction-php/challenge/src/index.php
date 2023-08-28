<?php 
// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
?>

<!DOCTYPE html>
<html>

<head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>PHP login</title>
    <link rel="stylesheet" href="style.css">
</head>

<body>
    <h1>PHP login</h1>
    <div class="container">
        <form action="" method="POST">
            <label for="username">Username</label>
            <input type="text" name="username" id="username" required />
            <label for="password">Password</label>
            <input type="password" name="password" id="password" required />
            <button>Login</button>
        </form>
    </div>
    <?php
    $response = getResponse();
    if (isset($response)) {
        echo "<div class=\"container\">
            <p>{$response}</p>
        </div>";
    }
    ?>
</body>
</html>
<?php

function getResponse()
{
    if (!isset($_POST['username']) || !isset($_POST['password'])) {
        return NULL;
    }

    $username = $_POST['username'];
    $password = $_POST['password'];

    if (!is_string($username) || !is_string($password)) {
        return "Please provide username and password as string";
    }

    $tier = getUserTier($username, $password);

    if ($tier === NULL) {
        return "Invalid credentials";
    }

    $response = "Login successful. Welcome " . htmlspecialchars($username) . ".";

    if ($tier === "gold") {
        $response .= " " . getenv("FLAG");
    }

    return $response;
}

function getUserTier($username, $password)
{
    $host = getenv("DB_HOST");
    $dbname = getenv("MYSQL_DATABASE");
    $charset = "utf8";
    $port = "3306";

    $sql_username = "forge";
    $sql_password = getenv("MYSQL_PASSWORD");
    try {
        $pdo = new PDO(
            dsn: "mysql:host=$host;dbname=$dbname;charset=$charset;port=$port",
            username: $sql_username,
            password: $sql_password,
        );

        $stmt = $pdo->prepare("SELECT password_hash, tier FROM Users WHERE username = ?");
        $stmt->execute([$username]);
        if ($row = $stmt->fetch()) {
            if (password_verify($password, $row['password_hash'])) {
                return $row['tier'];
            }
            var_dump($row);
        }
        return NULL;

    } catch (PDOException $e) {
        throw new PDOException(
            message: $e->getMessage(),
            code: (int) $e->getCode()
        );
    }
}

?>