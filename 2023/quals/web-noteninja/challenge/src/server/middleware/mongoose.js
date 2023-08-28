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

import mongoose from "mongoose";
import CryptoJS from "crypto-js";
import User from "../models/User";
import Note from "../models/Note";

const connectDb = (handler) => async (req, res) => {
  if (mongoose.connections[0].readyState) {
    return handler(req, res);
  }

  mongoose.set("strictQuery", false);
  mongoose.connect(process.env.MONGO_URL);

  try {
    const adminUser = await User.findOne({ email: process.env.ADMIN_EMAIL })
    if (!adminUser) {
      let u = new User({
        name: process.env.ADMIN_NAME,
        email: process.env.ADMIN_EMAIL,
        password: CryptoJS.AES.encrypt(
          process.env.ADMIN_PASS,
          process.env.SECRET_KEY
        ).toString(),
      });
      await u.save();

      const newNote = await Note({
        _userId: u._id,
        title: 'flag',
        description: process.env.FLAG,
        htmlDescription: process.env.FLAG
      });
      await newNote.save();

    }
  } catch (error) {
    console.log("admin creation failed: " + error);
  }
  return handler(req, res);
};

export default connectDb;
