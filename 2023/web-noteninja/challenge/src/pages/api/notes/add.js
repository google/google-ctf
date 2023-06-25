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
  if (req.method !== "POST") {
    res
      .status(400)
      .json({ hasError: true, message: "This method is not allowed" });
    return;
  }
  if (!req.body.title) {
    res.status(400).json({ hasError: true, message: "Title Required!" });
    return;
  }

  try {
    // asciidoctor
    const Asciidoctor = asciidoctor()
    const htmlDescription = Asciidoctor.convert(req.body.description, { standalone: true,safe: 'secure' }) 
    
    const userId = req.id;
    const newNote = await Note({
      ...req.body,
    });
    newNote._userId = userId;
    newNote.htmlDescription = htmlDescription;  

    await newNote.save();

    res
      .status(200)
      .json({ hasError: false, message: "Note added successfully!" });
  } catch (error) {
    res.status(500).json({ hasError: true, message: error.message });
  }
};

export default cors(verifyUser(connectDb(handler)));
