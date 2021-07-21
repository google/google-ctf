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
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/gorilla/sessions"
)

var (
	// key must be 16, 24 or 32 bytes long (AES-128, AES-192 or AES-256)
	key        = []byte("9327c659e0f6492a911ba7f7959ae2cd")
	batchTimer = 3 //seconds
)

type Resettable interface {
	Reset() error
}

func startBatchTimer(batching ...Resettable) { // b *batch.Batch, s1 *spamcounter.Counter, s2 *spamcounter.Counter) {
	ticker := time.NewTicker(time.Duration(batchTimer) * time.Second)
	go func() {
		for {
			<-ticker.C
			for _, b := range batching {
				err := b.Reset()
				if err != nil {
					fmt.Printf("Batch error %s\n", err)
				}
			}
		}
	}()
}

func defaultS(k string, d string) string {
	if envVar, exists := os.LookupEnv(k); exists {
		return envVar
	}
	return d
}
func defaultB(k string, d bool) bool {
	if envVar, exists := os.LookupEnv(k); exists {
		if val, err := strconv.ParseBool(envVar); err == nil {
			return val
		}
	}
	return d
}

func main() {
	port := defaultS("PORT", "1337")
	dbHost := defaultS("DB_HOST", "127.0.0.1")
	dbPort := defaultS("DB_PORT", "3306")
	dbPass := defaultS("DB_PASS", "password")
	dbUser := defaultS("DB_USER", "ctf")
	dbName := defaultS("DB_NAME", "ctf")
	connStr := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", dbUser, dbPass, dbHost, dbPort, dbName)
	db, err := sql.Open("mysql", connStr)
	if err != nil {
		fmt.Println(err)
		return
	}

	static, err := NewStatic()
	if err != nil {
		fmt.Println(err)
		return
	}
	b := NewBatch(db)
	r := NewRecent(db)
	pollSpammer := NewSpamcounter(2)
	messageSpammer := NewSpamcounter(5)
	otherSpammer := NewSpamcounter(50)
	store := sessions.NewCookieStore(key)

	fh := NewFriends(db)
	ph := NewPoll(r)
	mh := NewMessage(b)
	ah := NewAuthHandler(db, store, fh)
	dbr := NewDBReset(db)

	http.HandleFunc("/login", ah.Login)
	http.HandleFunc("/logout", ah.Logout)
	http.HandleFunc("/register", WrapCaptcha(ah.Register))
	http.HandleFunc("/invitecode", ah.Invite)
	// username to uuid
	http.HandleFunc("/user", ah.Wrap(otherSpammer.Wrap(ah.UserToUUID)))

	http.HandleFunc("/message", ah.Wrap(messageSpammer.Wrap(mh.Message)))

	http.HandleFunc("/poll", ah.Wrap(pollSpammer.Wrap(ph.Poll)))

	http.HandleFunc("/newroom", ah.Wrap(otherSpammer.Wrap(fh.AddRoom)))
	http.HandleFunc("/joinroom", ah.Wrap(otherSpammer.Wrap(fh.JoinRoom)))
	http.HandleFunc("/inviteroom", ah.Wrap(otherSpammer.Wrap(fh.InviteToRoom)))
	http.HandleFunc("/leaveroom", ah.Wrap(otherSpammer.Wrap(fh.LeaveRoom)))
	http.HandleFunc("/getrooms", ah.Wrap(otherSpammer.Wrap(fh.Get)))

	http.HandleFunc("/", static.Handle)
	startBatchTimer(b, messageSpammer, otherSpammer, ph, pollSpammer, NewFlag(b), r)

	ticker := time.NewTicker(time.Duration(48) * time.Hour)
	go func() {
		for {
			dbr.Reset()
			<-ticker.C
		}
	}()

	http.ListenAndServe(fmt.Sprintf(":%s", port), nil)
}
