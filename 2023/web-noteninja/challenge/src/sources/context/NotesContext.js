/**
 * Copyright 2023 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { useRouter } from "next/router";
import { toast } from "react-toastify";

const { createContext, useEffect, useState } = require("react");

export const NotesContext = createContext();

const NotesProvider = (props) => {
  const router = useRouter();
  const notesInitial = [];
  const [notes, setNotes] = useState(notesInitial);
  const [login, setLogin] = useState({ isLoggedIn: undefined, data: null });

  // Custom Fetch
  const doFetch = async (path, options = {}) => {
    const res = await fetch(path, {
      ...options,
      credentials: options.credentials || "include",
      headers: {
        ...options.headers,
        
        "Content-Type": "application/json",
      },
    });
    const response = await res.json();

    return response;
  };

  // Authentications
  const isLoggedIn = async () => {
    const response = await doFetch("/api/auth/loginstatus");
    setLogin(response);
  };

  const logout = async (redirect) => {
    let response = await doFetch("/api/auth/logout");
    setLogin(response);
    router.push(redirect || "/");
  };

  const getNotes = async (req, res) => {
    const response = await doFetch("/api/notes/allnotes");
    if (response.hasError) {
      toast.error(response.message);
      return;
    }
    setNotes(response.notes);
  };

  const updateNote = async (id, note) => {
    let response = await doFetch("/api/notes/" + id, {
      method: "PUT",
      body: JSON.stringify(note),
    });

    toast[response.hasError ? "error" : "success"](response.message);
  };

  const deleteNote = async (id) => {
    let response = await doFetch("/api/notes/" + id, {
      method: "DELETE",
    });

    getNotes();

    toast[response.hasError ? "error" : "success"](response.message);
  };

  useEffect(() => {
    isLoggedIn();
  }, [router.asPath]);

  return (
    <NotesContext.Provider
      value={{
        login,
        setLogin,
        logout,
        doFetch,
        getNotes,
        deleteNote,
        updateNote,
        notes,
      }}
    >
      {props.children}
    </NotesContext.Provider>
  );
};

export default NotesProvider;
