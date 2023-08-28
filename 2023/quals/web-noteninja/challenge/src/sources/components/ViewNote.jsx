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

import React, { useContext, useEffect, useState } from "react";
import Loading from "./UI/Loading";
import { NotesContext } from "../context/NotesContext";
import { toast } from "react-toastify";
import Router from "next/router";
import { IoReturnUpBack } from "react-icons/io5";
import { MdReportGmailerrorred } from "react-icons/md";
import Link from "next/link";

const ViewNote = (props) => {
  const { id } = props;
  const [note, setNote] = useState(undefined);
  const { doFetch } = useContext(NotesContext);

  const handleReport = async () => {
    toast["success"]("Reported to admin successfully!");
    let response = await doFetch("/api/notes/report",{method: "POST", body: JSON.stringify({id: id})});
  };

  useEffect(() => {
    const fetchNote = async () => {
      const response = await doFetch("/api/notes/" + id);
      if (response.hasError) {
        toast.error(response.message);
        Router.push("/");
        return;
      }

      setNote(response.note);
    };
    id && fetchNote();
  }, [id]);

  if (note === undefined) {
    return <Loading />;
  }

  return (
    <div className="flex items-center flex-col mt-10 gap-5">
      <span className="text-4xl font-semibold">Your Note:</span>
      <div className="w-[600px] mt-3 flex flex-col gap-2 p-3 border-4 border-gray-300 border-solid rounded-lg">
        <h2 className="">{note.title}</h2>

        <div className="border-t border-solid border-gray-300 my-2" />

        <div>
          {note.description ? (
            <iframe srcdoc={note.htmlDescription}  frameborder="0" />
            ) : (
            <div className="text-sm text-[#3d3d3d]">No Description</div>
          )}
        </div>

        <div className="border-t border-solid border-gray-300 my-2" />

        <div className="flex items-center gap-1">
          {note.tags ? (
            note.tags
              .trim()
              .split(",")
              .map((elem, ind) => (
                <span
                  key={ind}
                  className="bg-[#454545] text-sm text-white p-1 rounded-full px-2"
                >
                  {elem}
                </span>
              ))
          ) : (
            <div className="text-sm text-[#3d3d3d]">No Tags</div>
          )}
        </div>
      </div>

      <div className="flex items-center gap-4">
        <Link
          href="/"
          className="flex justify-center items-center gap-2 border-4 p-2 w-[100px] rounded-full border-[#989898] hover:border-[#5c5c5c] border-solid duration-300 cursor-pointer text-black	"
        >
          <IoReturnUpBack /> Back
        </Link>

        <div
          onClick={handleReport}
          className="flex justify-center items-center gap-2 border-4 border-red-300 p-2 w-[100px] rounded-full hover:border-red-600 border-solid duration-300 cursor-pointer"
        >
          <MdReportGmailerrorred /> Report
        </div>
      </div>
    </div>
  );
};

export default ViewNote;
