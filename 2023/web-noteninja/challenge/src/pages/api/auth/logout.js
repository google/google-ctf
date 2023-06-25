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

import verifyUser from "@/server/middleware/verifyUser";
import connectDb from "@/server/middleware/mongoose";
import cookie from "cookie";
import cors from "@/server/middleware/cors";

const handler = async (req, res) => {
  const cookies = req.headers?.cookies || req.cookies;
  const token = cookies["token"];

  if (token) {
    res.setHeader(
      "Set-Cookie",
      cookie.serialize("token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV !== "development",
        maxAge: -1,
        sameSite: "strict",
        path: "/",
        domain:
          process.env.NODE_ENV === "development"
            ? "localhost"
            : "",
      })
    );

    res.status(200).json({ isLoggedIn: false, data: null });
  } else {
    res.status(200).json({ isLoggedIn: false, data: null });
  }
};

export default cors(verifyUser(connectDb(handler)));
