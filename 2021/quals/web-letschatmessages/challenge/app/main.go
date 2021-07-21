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
	cryptoRand "crypto/rand"
	"database/sql"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
)

var (
	db          *sql.DB
	messagePath = "/"
	cache       map[string]resErr
	lock        sync.Mutex
)

type resErr struct {
	res string
	err error
}

func getMessage(id uuid.UUID) (string, error) {
	idStr := id.String()
	lock.Lock()
	defer lock.Unlock()
	if _, ok := cache[idStr]; !ok {
		lock.Unlock()
		query := "SELECT message FROM messages WHERE id = ?"
		res, err := SingleString(db, query, idStr)
		lock.Lock()
		cache[idStr] = resErr{res: res, err: err}
	}
	return cache[idStr].res, cache[idStr].err
}

func handleMessage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)

	id, err := ToUUID(strings.TrimLeft(r.URL.Path, messagePath))
	if err != nil {
		http.Error(w, "Invalid UUID", 500)
		return
	}
	message, err := getMessage(id)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if strings.HasPrefix(message, "Player") {
		message = "Player:*******"
	}
	w.Write([]byte(message))
}

func main() {
	port := DefaultS("PORT", "1337")
	dev := DefaultB("DEV", false)

	randBuf := make([]byte, 8)
	if _, err := cryptoRand.Read(randBuf); err != nil {
		fmt.Println(err)
		return
	}
	rand.Seed(int64(binary.BigEndian.Uint64(randBuf)))

	cache = map[string]resErr{}
	var err error
	if dev {
		fmt.Println("connecting to the local thing")
		db, err = sql.Open("mysql", "ctf:kajsdfouyhsdfhl@tcp(127.0.0.1:3306)/ctf")
		if err != nil {
			fmt.Println(err)
			return
		}
	} else {
		ipAddrs := []string{
			"10.59.2.2",
		}
		n := rand.Int() % len(ipAddrs)
		ipAddr := ipAddrs[n]
		db, err = sql.Open("mysql", "ctf:Gj36GdD4n6OaALwk1@tcp("+ipAddr+":3306)/ctf")
		db.SetMaxOpenConns(200)
		db.SetMaxIdleConns(0)
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	ticker := time.NewTicker(time.Duration(10) * time.Minute)
	go func() {
		for {
			<-ticker.C
			lock.Lock()
			cache = map[string]resErr{}
			lock.Unlock()
		}
	}()
	http.HandleFunc(messagePath, handleMessage)

	http.ListenAndServe(fmt.Sprintf(":%s", port), nil)
}
