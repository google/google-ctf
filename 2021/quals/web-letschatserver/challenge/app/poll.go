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
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	"github.com/google/uuid"
)

type PollHandler struct {
	r               *Recent
	roomToMessageID map[string][]string
	lock            sync.RWMutex
}

func (h *PollHandler) Reset() error {
	h.lock.Lock()
	h.roomToMessageID = h.r.LatestMessages()
	h.lock.Unlock()
	return nil
}

func lastMessageTime(id string) uuid.Time {
	uid, err := ToUUID(id)
	if err != nil {
		uid, _ = uuid.Parse("00000000-0000-0000-0000-000000000000")
	}
	t := uid.Time()
	return t
}

func (h *PollHandler) Poll(w http.ResponseWriter, r *http.Request, user uuid.UUID) {
	results := map[string][]string{}
	rooms := strings.Split(r.FormValue("rooms"), ",")
	if len(rooms) > 10 {
		Error("You are in too many rooms!", w)
		return
	}

	h.lock.RLock()
	for _, roomAndLastMessage := range rooms {
		roomId := strings.Split(roomAndLastMessage, ":")
		room := roomId[0]
		if room == "" {
			continue
		}
		lastMessage := lastMessageTime("")
		if len(roomId) == 2 {
			lastMessage = lastMessageTime(roomId[1])
		}
		if len(h.roomToMessageID[room]) == 0 {
			continue
		}
		for _, msgID := range h.roomToMessageID[room] {
			uid, _ := ToUUID(msgID)
			time := uid.Time()
			if lastMessage < time {
				results[room] = append(results[room], msgID)
			}
		}
	}
	h.lock.RUnlock()

	resultStr, err := json.Marshal(results)
	if err != nil {
		Error(err.Error(), w)
		return
	}
	SuccessJSON(string(resultStr), w)
}

func NewPoll(r *Recent) *PollHandler {
	return &PollHandler{
		r:               r,
		roomToMessageID: map[string][]string{},
	}
}
