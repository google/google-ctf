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
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

type MessageHandler struct {
	b *Batch
}

func (h *MessageHandler) extractMessage(r *http.Request, user uuid.UUID) (*MessageRow, error) {
	to := r.FormValue("to")
	message := r.FormValue("message")

	return &MessageRow{
		From:    user,
		To:      to,
		Message: message,
	}, nil
}

func (h *MessageHandler) Message(w http.ResponseWriter, r *http.Request, user uuid.UUID) {
	userMessage, err := h.extractMessage(r, user)
	if err != nil {
		Error(err.Error(), w)
		return
	}
	if len(userMessage.Message) > 200 {
		Error("Message too long", w)
		return
	}
	// hack for the bot 0000... is the bot so don't do anything to the message.
	if user.String() != "00000000-0000-0000-0000-000000000000" {
		userMessage.Message = fmt.Sprintf("Player%s:%s", strings.Split(user.String(), "-")[0], userMessage.Message)
	}
	h.b.Add(userMessage)
	Success("OK", w)
}

func NewMessage(b *Batch) *MessageHandler {
	return &MessageHandler{
		b: b,
	}
}
