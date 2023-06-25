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

import cors from "@/server/middleware/cors";
import connectDb from "@/server/middleware/mongoose";
import verifyUser from "@/server/middleware/verifyUser";
import Note from "@/server/models/Note";
import asciidoctor from 'asciidoctor' ;

const handler = async (req, res) => {
  if (req.method !== "GET" && req.method !== "PUT" && req.method !== "DELETE") {
    res
      .status(400)
      .json({ hasError: true, message: "This method not allowed" });
    return;
  }

  const { id } = req.query;
  if (!id) {
    res.status(500).json({ hasError: true, message: "Somthing went wrong" });
    return;
  }

  const note = await Note.findOne({ _id: id });
  if (!note) {
    res.status(400).json({ hasError: true, message: "No note found!" });
    return;
  }
  if (req.id !== note._userId) {
    if (req.user.email !== process.env.ADMIN_EMAIL) {
      res.status(400).json({ hasError: true, message: "This is not your note!" });
      return;
    }
  }

  if (req.method === "GET") {
    res.status(200).json({ hasError: false, note: note });
  } else if (req.method === "DELETE") {
    try {
      await Note.findByIdAndDelete(id);
      res
        .status(200)
        .json({ hasError: false, message: "Note deleted successfully" });
    } catch (error) {
      res
        .status(500)
        .json({ hasError: true, message: "Internal Server Error" });
    }
  } else if (req.method === "PUT") {
    if (!req.body.title) {
      res.status(400).json({ hasError: true, message: "Title Required!" });
      return;
    }

    try {

      // asciidoctor
      const Asciidoctor = asciidoctor()
      const htmlDescription = Asciidoctor.convert(req.body.description, { standalone: true,safe: 'secure' }) 
    
      await Note.findByIdAndUpdate(id, { ...req.body, htmlDescription: htmlDescription });
      res
        .status(200)
        .json({ hasError: false, message: "Note updated successfully!" });
    } catch (error) {
      res.status(500).json({ hasError: true, message: error.message });
    }
  }
};

export default cors(verifyUser(connectDb(handler)));
