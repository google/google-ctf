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

import connectDb from "@/server/middleware/mongoose";
import jwt from "jsonwebtoken";
import cors from "@/server/middleware/cors";

const handler = async (req, res) => {
  const cookies = req.headers?.cookies || req.cookies;
  const user = cookies["token"];

  if (!user) {
    res.status(200).json({
      isLoggedIn: false,
      data: null,
    });
  } else {
    try {
      const data = jwt.verify(user, process.env.JWT_SECRET);

      data
        ? res.status(200).json({ isLoggedIn: true, data: data })
        : res.status(200).json({ isLoggedIn: false, data: null });
      if (!data) {
        res.status(200).json({
          isLoggedIn: false,
          msg: err,
          data: null,
        });
      }
    }
    catch (err) {
      res.status(500).json({ isLoggedIn: false, data: null, msg: err.message })
    }
  }
};

export default cors(connectDb(handler));
