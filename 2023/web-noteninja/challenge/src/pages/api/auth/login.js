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

import cookie from "cookie";
import CryptoJS from "crypto-js";
import cors from "@/server/middleware/cors";
import User from "@/server/models/User";
import connectDb from "@/server/middleware/mongoose";
var jwt = require("jsonwebtoken");

let jwtSecret = process.env.JWT_SECRET;
let secret = process.env.SECRET_KEY;

const handler = async (req, res) => {
  if (req.method === "POST") {
    const { email, password, captchaToken } = req.body;

    const recaptchasecret = process.env.RECAPTCHA_SECRET_KEY;
    const remoteip = req.socket.remoteAddress;

    const response = await fetch(
      `https://www.google.com/recaptcha/api/siteverify`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: `secret=${recaptchasecret}&response=${captchaToken}&remoteip=${remoteip}`,
      }
    );

    const data = await response.json();
    if (data.success && data.score >= 0.0) {
      if (email !== "" && password !== "") {
        let user = await User.findOne({ email: email });
        if (user) {
          const bytes = CryptoJS.AES.decrypt(user.password, secret);
          const decryptedPassword = bytes.toString(CryptoJS.enc.Utf8);

          if (email === user.email && password === decryptedPassword) {
            const data = {
              exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7,
              email: user.email,
              id: user._id,
            };
            try {
              const token = jwt.sign(data, jwtSecret);

              res.setHeader(
                "Set-Cookie",
                cookie.serialize("token", token, {
                  httpOnly: true,
                  secure: process.env.NODE_ENV !== "development",
                  maxAge: 60 * 60 * 24 * 7,
                  sameSite: "strict",
                  path: "/",
                  domain:
                    process.env.NODE_ENV === "development" ? "localhost" : "",
                })
              );
            }
            catch (err) {
              res.status(500).json({ hasError: true, data: null, message: err.message })
            }

            res.status(200).json({
              hasError: false,
              message: "Successfully Loggedin!",
              data: data,
            });
          } else {
            res
              .status(400)
              .json({ hasError: true, message: "Invalid Credentials!" });
          }
        } else {
          res.status(400).json({
            hasError: true,
            message: "Email doesn't exist",
          });
        }
      } else {
        res
          .status(400)
          .json({ hasError: true, message: "Please provide credentials" });
      }
    } else {
      res.status(401).json({
        hasError: true,
        message: "reCAPTCHA verification failed - Your are robot",
      });
    }
  } else {
    res
      .status(400)
      .json({ hasError: true, message: "This method is not allowed!" });
  }
};

export default cors(connectDb(handler));
