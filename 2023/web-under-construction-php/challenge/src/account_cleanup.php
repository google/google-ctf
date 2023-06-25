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

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
	http_response_code(400);
	exit();
}

if(!isset($_SERVER['HTTP_TOKEN'])) {
	http_response_code(401);
	exit();
}

if($_SERVER['HTTP_TOKEN'] !== getenv("MIGRATOR_TOKEN")) {
	http_response_code(401);
	exit();
}


cleanup();


function cleanup() {}
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

		$pdo->exec("TRUNCATE TABLE Users;");
		echo "Table truncated";
	} catch (PDOException $e) {
		throw new PDOException(
			message: $e->getMessage(),
			code: (int) $e->getCode()
		);
	}
}



?>
