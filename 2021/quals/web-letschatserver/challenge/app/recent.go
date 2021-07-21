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
	"sync"
)

type Recent struct {
	lastBatch []*ForPoll
	db        *sql.DB
	lock      sync.Mutex
}

type ForPoll struct {
	To string
	Id string
}

func (b *Recent) LatestMessages() map[string][]string {
	b.lock.Lock()
	defer b.lock.Unlock()
	latest := map[string][]string{}
	for _, message := range b.lastBatch {
		// lets cap it at 500  messages per room
		if len(latest[message.To]) > 500 {
			continue
		}
		latest[message.To] = append(latest[message.To], message.Id)
	}
	return latest
}

func (b *Recent) Reset() error {
	q := "SELECT room_id, id FROM messages order by `time` desc limit 5000"
	rows, err := b.db.Query(q)
	if err != nil {
		return err
	}
	messages := []*ForPoll{}
	for rows.Next() {
		var message string
		var id string
		switch err := rows.Scan(&message, &id); err {
		case sql.ErrNoRows:
			return nil
		case nil:
			messages = append(messages, &ForPoll{
				To: message,
				Id: id,
			})
		default:
			return fmt.Errorf(fmt.Sprintf("Unhandled response from Scan(): %s", err))
		}
	}
	b.lock.Lock()
	b.lastBatch = messages
	b.lock.Unlock()
	return nil
}

func NewRecent(conn *sql.DB) *Recent {
	return &Recent{
		db: conn,
	}
}
