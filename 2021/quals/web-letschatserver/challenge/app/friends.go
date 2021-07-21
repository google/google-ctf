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
	"strings"

	"github.com/google/uuid"
)

type Handler struct {
	db *sql.DB
}

func (h *Handler) getRooms(user uuid.UUID) ([]string, error) {
	sqlStatement := `SELECT room_id from rooms where player_id = ?`
	//WHERE first.id = ?
	//and EXISTS (SELECT FROM friends as second where first.friends_with = second.id and first.id = second.friends_with)
	//`
	rows, err := h.db.Query(sqlStatement, user.String())
	if err != nil {
		return nil, err
	}

	var ids []string
	for rows.Next() {
		var id string
		switch err := rows.Scan(&id); err {
		case sql.ErrNoRows:
			return nil, fmt.Errorf("No rooms")
		case nil:
			ids = append(ids, id)
		default:
			return nil, fmt.Errorf(fmt.Sprintf("Unhandled response from Scan() on get rooms: %s", err))
		}
	}
	return ids, nil
}

func (h *Handler) do(q string, args ...string) error {
	tx, err := h.db.Begin()
	stmt, err := tx.Prepare(q)
	if err != nil {
		fmt.Println(err)
		return err
	}
	argsI := []interface{}{}
	for _, arg := range args {
		argsI = append(argsI, arg)
	}
	_, err = stmt.Exec(argsI...)
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

func (h *Handler) leaveRoom(room string, player uuid.UUID) error {
	return h.do(`DELETE FROM rooms WHERE room_id = ? and player_id = ?`, room, player.String())
}

func (h *Handler) insertRoom(room string, player uuid.UUID) error {
	return h.do(`INSERT INTO rooms (room_id, player_id) VALUES (?, ?)`, room, player.String())
}
func (h *Handler) DoInvite(room string, player uuid.UUID) error {
	return h.do(`INSERT INTO invites (room_id, player_id) VALUES (?, ?)`, room, player.String())
}

func (h *Handler) roomExists(room string) (bool, error) {
	_, err := SingleString(h.db, "SELECT room_id FROM rooms WHERE room_id = ?", room)
	if err != nil {
		switch err.(type) {
		case NoResults:
			return false, nil
		default:
			return false, err
		}
	}
	return true, nil
}

func (h *Handler) extractUUID(r *http.Request, field string) (uuid.UUID, error) {
	friend, err := ToUUID(r.FormValue(field))
	if err != nil {
		return uuid.UUID{}, err
	}

	return friend, nil
}

func (h *Handler) LeaveRoom(w http.ResponseWriter, r *http.Request, user uuid.UUID) {
	room := r.FormValue("roomName")
	go func() {
		err := h.leaveRoom(room, user)
		if err != nil {
			fmt.Println(err)
		}
	}()
	Success("OK", w)
}

func (h *Handler) Get(w http.ResponseWriter, r *http.Request, user uuid.UUID) {
	rooms, err := h.getRooms(user)
	if err != nil {
		Error(err.Error(), w)
		return
	}
	Success(strings.Join(rooms, ","), w)
}

func (h *Handler) AddRoom(w http.ResponseWriter, r *http.Request, user uuid.UUID) {
	roomName := r.FormValue("roomName")
	if roomName == "Errors" {
		Error("Reserved room name", w)
		return
	}

	if strings.Contains(roomName, ",") || strings.Contains(roomName, ":") {
		Error("Room name can't contain : or ,", w)
		return
	}
	if len(roomName) > 50 {
		Error("Room name too long", w)
		return
	}
	exists, err := h.roomExists(roomName)
	if err != nil {
		Error(err.Error(), w)
		return
	}
	if exists {
		Error("Room already exists", w)
		return
	}

	err = h.insertRoom(roomName, user)
	if err != nil {
		Error(err.Error(), w)
		return
	}
	Success("OK", w)
}

func (h *Handler) hasRoomInvite(room string, user uuid.UUID) (bool, error) {
	query := "SELECT room_id from invites where room_id = ? and player_id = ?"
	row := h.db.QueryRow(query, room, user.String())
	var roomName string
	switch err := row.Scan(&roomName); err {
	case sql.ErrNoRows:
		return false, nil
	case nil:
		return true, nil
	default:
		return false, fmt.Errorf("Unhandled response from Scan() on login")
	}
	return false, fmt.Errorf("can't get here")
}

func (h *Handler) isInRoom(room string, user uuid.UUID) (bool, error) {
	query := "SELECT room_id from rooms where room_id = ? and player_id = ?"
	row := h.db.QueryRow(query, room, user.String())
	var roomName string
	switch err := row.Scan(&roomName); err {
	case sql.ErrNoRows:
		return false, nil
	case nil:
		return true, nil
	default:
		return false, fmt.Errorf("Unhandled response from Scan(): %s", err)
	}
	return false, fmt.Errorf("can't get here")
}

func (h *Handler) JoinRoom(w http.ResponseWriter, r *http.Request, user uuid.UUID) {
	roomName := r.FormValue("roomName")
	userHasPermission, err := h.hasRoomInvite(roomName, user)
	if err != nil {
		Error(err.Error(), w)
		return
	}
	if !userHasPermission {
		Error("Must be invited to join a room", w)
		return
	}
	err = h.insertRoom(roomName, user)
	if err != nil {
		Error(err.Error(), w)
		return
	}
	Success("OK", w)
}

func (h *Handler) InviteToRoom(w http.ResponseWriter, r *http.Request, user uuid.UUID) {
	roomName := r.FormValue("roomName")
	toInvite, err := h.extractUUID(r, "toInvite")
	if err != nil {
		Error(err.Error(), w)
		return
	}
	userHasPermission, err := h.isInRoom(roomName, user)
	if err != nil {
		Error(err.Error(), w)
		return
	}
	if !userHasPermission {
		Error("Must already be in room to invite someone else", w)
		return
	}
	err = h.DoInvite(roomName, toInvite)
	if err != nil {
		Error(err.Error(), w)
		return
	}
	Success("OK", w)
}

func NewFriends(db *sql.DB) *Handler {
	return &Handler{
		db: db,
	}
}
