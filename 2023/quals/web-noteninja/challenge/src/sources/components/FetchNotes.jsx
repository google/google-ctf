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

import Link from "next/link";
import React, { useContext, useEffect, useState } from "react";
import { FcFullTrash, FcInfo } from "react-icons/fc";
import { GrEdit, GrFormAdd } from "react-icons/gr";
import { AiFillEye } from "react-icons/ai";
import Loading from "./UI/Loading";
import { NotesContext } from "../context/NotesContext";
import { toast } from "react-toastify";
import Router from "next/router";

const NotesItem = ({ note }) => {
  const { deleteNote, updateNote } = useContext(NotesContext);

  return (
    <div className="relative truncate w-[300px] h-[120px] bg-[#FFBF00] p-3 shadow-lg">
      <Link
        href={`/notes/${note._id}`}
        className="overflow-ellipsis text-xl font-semibold"
      >
        {note.title}
      </Link>

      <div className="absolute bottom-3 left-3 flex text-3xl items-center gap-3">
        <AiFillEye
          onClick={() => Router.push(`/notes/${note._id}`)}
          className="cursor-pointer text-white bg-[#37373774] rounded-lg p-1 h-8 w-12"
        />
        <FcFullTrash
          onClick={() => deleteNote(note._id)}
          className="cursor-pointer bg-[#37373774] rounded-lg p-1 h-8 w-12"
        />
        <GrEdit
          onClick={() => Router.push(`/edit/${note._id}`)}
          className="cursor-pointer bg-[#37373774] rounded-lg p-1 h-8 w-12"
        />
      </div>
    </div>
  );
};

const FetchNotes = () => {
  const { getNotes, notes } = useContext(NotesContext);

  useEffect(() => {
    getNotes();
  }, []);

  if (notes === undefined) {
    return <Loading height="h-[50vh]" />;
  }

  return (
    <div className="flex flex-wrap gap-5">
      {notes.map((note) => (
        <NotesItem key={note._id} note={note} />
      ))}

      <Link
        href="/add-note"
        className="w-[300px] h-[120px] p-[9px] shadow-lg flex items-center justify-center rounded-lg border-4 border-solid border-[#646464]"
      >
        <GrFormAdd className="text-7xl" />
      </Link>
    </div>
  );
};

export default FetchNotes;
