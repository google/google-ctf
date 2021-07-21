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
	"strings"
	"sync"

	"github.com/google/uuid"
)

type Batch struct {
	lastBatch []*MessageRow
	toBatch   []*MessageRow
	db        *sql.DB
	lock      sync.Mutex
}

type MessageRow struct {
	From    uuid.UUID
	To      string
	Message string
	Id      uuid.UUID
}

func (b *Batch) LastBatch() []*MessageRow {
	return b.lastBatch
}

func addIds(b []*MessageRow) {
	for _, row := range b {
		row.Id, _ = uuid.NewUUID()
	}
}

func (b *Batch) Add(r *MessageRow) {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.toBatch = append(b.toBatch, r)
}

func (b *Batch) Reset() error {
	b.lock.Lock()
	sending := b.toBatch
	b.toBatch = []*MessageRow{}
	b.lock.Unlock()

	if len(sending) == 0 {
		return nil
	}

	addIds(sending)

	valueStrings := []string{}
	valueArgs := []string{}
	for _, row := range sending {
		valueStrings = append(valueStrings, "(?, ?, ?, ?, CURRENT_TIMESTAMP())")
		valueArgs = append(valueArgs, row.To)
		valueArgs = append(valueArgs, row.From.String())
		valueArgs = append(valueArgs, row.Id.String())
		valueArgs = append(valueArgs, row.Message)
	}
	qry := fmt.Sprintf(`INSERT INTO messages (room_id, from_id, id, message, time) VALUES %s`, strings.Join(valueStrings, ","))

	b.lastBatch = sending
	return Insert(b.db, qry, valueArgs...)
}

func NewBatch(conn *sql.DB) *Batch {
	return &Batch{
		db: conn,
	}
}
