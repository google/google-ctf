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
	"net/http"
	"sync"

	"github.com/google/uuid"
)

type Counter struct {
	m    map[string]int
	lock *sync.Mutex
	max  int
}

func (c *Counter) Register(u uuid.UUID) int {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.m[u.String()]++
	return c.m[u.String()]
}
func (c *Counter) Reset() error {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.m = map[string]int{}
	return nil
}

func (c *Counter) Wrap(toWrap func(http.ResponseWriter, *http.Request, uuid.UUID)) func(http.ResponseWriter, *http.Request, uuid.UUID) {
	return func(w http.ResponseWriter, r *http.Request, user uuid.UUID) {
		if c.Register(user) > c.max {
			Error("Too Fast!", w)
			return
		}
		toWrap(w, r, user)
	}
}

func NewSpamcounter(max int) *Counter {
	return &Counter{
		m:    map[string]int{},
		lock: &sync.Mutex{},
		max:  max,
	}
}
