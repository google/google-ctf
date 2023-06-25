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

import Router from "next/router";
import React, { useContext, useEffect, useState } from "react";
import { toast } from "react-toastify";
import { NotesContext } from "../context/NotesContext";
import Link from "next/link";
import { IoReturnUpBack } from "react-icons/io5";

const EditNotes = ({ id }) => {
  const initail = {
    title: "",
    description: "",
    tags: "",
  };
  const [form, setForm] = useState(initail);
  const { doFetch, updateNote } = useContext(NotesContext);

  useEffect(() => {
    const getNote = async () => {
      const response = await doFetch(`/api/notes/${id}`);
      if (response.hasError) {
        Router.push("/");
        toast.error(response.message);
        return;
      }

      setForm(response.note);
    };

    id && getNote();
  }, [id]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!form.title) {
      toast.error("Title Required!");
      return;
    }

    const response = await doFetch("/api/notes/" + id, {
      method: "PUT",
      body: JSON.stringify(form),
    });

    if (response.hasError) {
      toast.error(response.message);
      return;
    }

    setForm(initail);
    Router.push("/");
    toast.success(response.message);
  };

  const handleChange = (e) => {
    const name = e.target.name;
    const value = e.target.value;

    setForm((prev) => {
      const temp = { ...prev };
      temp[name] = value;
      return temp;
    });
  };

  return (
    <div className="flex items-center flex-col py-10">
      <div className="text-[40px] font-bold text-left">Edit Note:</div>

      <form
        onSubmit={handleSubmit}
        className="w-[600px] mt-3 flex flex-col gap-2 p-3 border border-solid border-[#848484] rounded-lg"
      >
        <input
          className="appearance-none border border-solid border-[#848484] rounded w-[573px] p-3"
          name="title"
          type="text"
          placeholder="Enter Title"
          value={form.title}
          onChange={handleChange}
        />
        <textarea
          className="appearance-none border border-solid border-[#848484] rounded w-[573px] p-3"
          name="description"
          rows={7}
          placeholder="Enter Description"
          value={form.description}
          onChange={handleChange}
        />
        <input
          className="appearance-none border border-solid border-[#848484] rounded w-[573px] p-3"
          name="tags"
          type="text"
          placeholder="Enter Tags (seperate with (,))"
          value={form.tags}
          onChange={handleChange}
        />
        <div className="flex items-center justify-between">
          <button
            className="bg-blue-500 hover:bg-blue-700 text-white font-bold px-4 py-3 text-[16px] cursor-pointer rounded border-none"
            type="submit"
          >
            Update Note
          </button>
        </div>
      </form>

      <Link
        href="/"
        className="flex justify-center items-center gap-2 border-4 p-2 w-[120px] rounded-full mt-5 border-[#a4a3a3] hover:border-[#5c5c5c] border-solid duration-300"
      >
        <IoReturnUpBack /> Back
      </Link>
    </div>
  );
};

export default EditNotes;
