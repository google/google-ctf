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

const jwt = require("jsonwebtoken");
const JWT_SECRET = process.env.JWT_SECRET;

const verifyUser = (handler, action) => {
  return async (req, res) => {
    const cookies = req.headers?.cookies || req.cookies;
    const user = cookies["token"];

    if (!user) {
      res.status(400).json({
        hasError: true,
        message:
          "You are not logged in. Please login first to access your account.",
      });
    } else {
      try {
        const data = jwt.verify(user, JWT_SECRET);
        req.id = data.id;
        req.user = data;

        if (data) {
          return handler(req, res);
        } else {
          res.status(401).json({
            hasError: true,
            message: "Token Expired! Please login again.",
          });
        }
      }
      catch (err) {
        res.status(500).json({ isLoggedIn: false, data: null, msg: err.message })
      }
    }
  };
};

export default verifyUser;
