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
	"net/http"
	"os"
	"strconv"

	"github.com/google/uuid"
)

func ToUUID(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}

func Error(s string, w http.ResponseWriter) {
	http.Error(w, s, 500)
}

func Success(s string, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write([]byte(s))
}

func SuccessJSON(s string, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write([]byte(s))
}

func DefaultS(k string, d string) string {
	if envVar, exists := os.LookupEnv(k); exists {
		return envVar
	}
	return d
}
func DefaultB(k string, d bool) bool {
	if envVar, exists := os.LookupEnv(k); exists {
		if val, err := strconv.ParseBool(envVar); err == nil {
			return val
		}
	}
	return d
}

func ToArgsI(args []string) []interface{} {
	argsI := []interface{}{}
	for _, arg := range args {
		argsI = append(argsI, arg)
	}
	return argsI
}

type NoResults error

func SingleString(db *sql.DB, q string, args ...string) (string, error) {
	row := db.QueryRow(q, ToArgsI(args)...)
	var message string
	switch err := row.Scan(&message); err {
	case sql.ErrNoRows:
		return "", NoResults(fmt.Errorf("No results"))
	case nil:
		return message, nil
	default:
		return "", fmt.Errorf(fmt.Sprintf("Unhandled response from Scan(): %s", err))
	}

}

func StringSlice(db *sql.DB, q string, args ...string) ([]string, error) {
	rows, err := db.Query(q, ToArgsI(args)...)
	if err != nil {
		return nil, err
	}
	messages := []string{}
	for rows.Next() {
		var message string
		switch err := rows.Scan(&message); err {
		case sql.ErrNoRows:
			return nil, NoResults(fmt.Errorf("No results"))
		case nil:
			messages = append(messages, message)
		default:
			return nil, fmt.Errorf(fmt.Sprintf("Unhandled response from Scan(): %s", err))
		}
	}
	return messages, nil
}

func Insert(db *sql.DB, q string, args ...string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(q)
	if err != nil {
		fmt.Println(err)
		return err
	}
	_, err = stmt.Exec(ToArgsI(args)...)
	if err != nil {
		tx.Rollback()
		return err
	}
	err = tx.Commit()
	if err != nil {
		return err
	}
	return nil
}
