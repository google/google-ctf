/**
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package main

import (
	"database/sql"
	"fmt"
)

var resetQueries = []string{`DROP TABLE IF EXISTS rooms;`, `
CREATE TABLE rooms (
room_id varchar(51) NOT NULL,
player_id char(36) NOT NULL
);
`, `DROP TABLE IF EXISTS invites;`, `
CREATE TABLE invites (
room_id varchar(51),
player_id char(36)
);`, `DROP TABLE IF EXISTS users;`, `
CREATE TABLE users (
username varchar(51),
password varchar(51),
id char(36),
PRIMARY KEY (username)
);`, `DROP TABLE IF EXISTS messages;`, `
CREATE TABLE messages (
room_id varchar(51),
from_id varchar(36),
id char(36),
message varchar(255),
time TIMESTAMP,
PRIMARY KEY (id)
);
`}

type ResetHandler struct {
	db *sql.DB
}

func (h *ResetHandler) Reset() {
	for _, resetQuery := range resetQueries {
		if err := Insert(h.db, resetQuery); err != nil {
			fmt.Printf("Error resseing the DB: %s", err)
			return
		}
	}
}

func NewDBReset(db *sql.DB) *ResetHandler {
	return &ResetHandler{
		db: db,
	}
}
