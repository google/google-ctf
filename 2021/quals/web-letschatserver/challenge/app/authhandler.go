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

	"github.com/gorilla/sessions"

	"github.com/google/uuid"
)

var (
	cookieName = "session"
)

type Auth struct {
	db    *sql.DB
	store *sessions.CookieStore
	f     *Handler
}

func (a *Auth) User(r *http.Request) (uuid.UUID, error) {
	session, err := a.store.Get(r, cookieName)
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("Invalid cookie")
	}
	id, ok := session.Values["id"].(string)
	if !ok {
		return uuid.UUID{}, fmt.Errorf("Not logged in")
	}
	return ToUUID(id)
}

func (a *Auth) Wrap(toWrap func(http.ResponseWriter, *http.Request, uuid.UUID)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := a.User(r)
		if err != nil {
			Error("Not logged in", w)
			return
		}
		toWrap(w, r, user)
	}
}
func (a *Auth) Invite(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "don't even bother", 404)
}

func (a *Auth) UserToUUID(w http.ResponseWriter, r *http.Request, user uuid.UUID) {
	lookupUser := r.FormValue("username")
	uuid, err := a.usernameQuery(lookupUser)
	if err != nil {
		Error(err.Error(), w)
		return
	}
	Success(uuid.String(), w)
}

func (a *Auth) Register(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	if len(username) > 50 {
		Error("Username too long", w)
		return
	}
	password := r.FormValue("password")
	if len(password) > 50 {
		Error("Password too long", w)
		return
	}
	id, _ := uuid.NewUUID()
	err := a.registerQuery(username, password, id)
	if err != nil {
		Error(err.Error(), w)
		return
	}
	err = a.f.DoInvite("Public", id)
	if err != nil {
		Error(err.Error(), w)
		return
	}
	Success("OK", w)
}

func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	session, err := a.store.Get(r, cookieName)
	if err != nil {
		Error(err.Error(), w)
		return
	}
	session.Options.MaxAge = -1
	err = session.Save(r, w)
	if err != nil {
		Error(err.Error(), w)
		return
	}
	Success("OK", w)
}

func parseForm(r *http.Request) (username string, password string, err error) {
	err = r.ParseForm()
	if err != nil {
		return
	}
	username = r.PostForm.Get("username")
	password = r.PostForm.Get("password")
	if username == "" || password == "" {
		err = fmt.Errorf("Empty username or password")
	}
	return
}

func (a *Auth) registerQuery(u string, p string, id uuid.UUID) error {
	sqlStatement := `INSERT INTO users (username, password, id) VALUES (?, ?, ?)`
	tx, err := a.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(sqlStatement)
	if err != nil {
		fmt.Println(err)
		return err
	}
	_, err = stmt.Exec(u, p, id.String())
	if err != nil {
		tx.Rollback()
		fmt.Println(err)
		return err
	}
	err = tx.Commit()
	if err != nil {
		fmt.Println(err)
		return err
	}
	return nil
}

func (a *Auth) usernameQuery(u string) (uuid.UUID, error) {
	sqlStatement := `SELECT id FROM users WHERE username = ? `
	user, err := SingleString(a.db, sqlStatement, u)
	if err != nil {
		return uuid.UUID{}, err
	}
	return ToUUID(user)
}

func (a *Auth) loginQuery(u string, p string) (uuid.UUID, error) {
	sqlStatement := `SELECT id FROM users WHERE username = ? and password = ?;`
	user, err := SingleString(a.db, sqlStatement, u, p)
	if err != nil {
		return uuid.UUID{}, err
	}
	return ToUUID(user)
}

func (a *Auth) Login(w http.ResponseWriter, r *http.Request) {
	username, password, err := parseForm(r)
	if err != nil {
		Error(err.Error(), w)
		return
	}

	uuid, err := a.loginQuery(username, password)
	if err != nil {
		Error(err.Error(), w)
		return
	}

	session, err := a.store.Get(r, cookieName)
	if err != nil {
		Error(err.Error(), w)
		return
	}
	session.Values["id"] = uuid.String()
	session.Save(r, w)

	Success(uuid.String(), w)
}

func NewAuthHandler(db *sql.DB, store *sessions.CookieStore, f *Handler) *Auth {
	return &Auth{
		db:    db,
		store: store,
		f:     f,
	}
}
