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

import User from "@/server/models/User";
import connectDb from "@/server/middleware/mongoose";
import CryptoJS from "crypto-js";
import cors from "@/server/middleware/cors";

const handler = async (req, res) => {
  if (req.method === "POST") {
    const { name, email, password, captchaToken } = req.body;

    const secret = process.env.RECAPTCHA_SECRET_KEY;
    const remoteip = req.socket.remoteAddress;

    const response = await fetch(
      `https://www.google.com/recaptcha/api/siteverify`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: `secret=${secret}&response=${captchaToken}&remoteip=${remoteip}`,
      }
    );

    const data = await response.json();
    console.log(data)
    if (data.success && data.score >= 0.0) {
      let emailAvailable = await User.findOne({ email: email });

      if (emailAvailable) {
        res.status(409).json({
          hasError: true,
          message: `This email is already exists`,
        });
      } else {
        try {
          let u = new User({
            name: name,
            email: email,
            password: CryptoJS.AES.encrypt(
              password,
              process.env.SECRET_KEY
            ).toString(),
          });
          await u.save();

          res.status(200).json({
            hasError: false,
            message: "Account Created Successfully!",
          });
        } catch (error) {
          res.status(500).json({ hasError: true, message: error.message });
        }
      }
    } else {
      res
        .status(401)
        .json({ hasError: true, message: "reCAPTCHA verification failed - You are robot" });
    }
  } else {
    res
      .status(405)
      .json({ hasError: true, message: "This method is not accepted" });
  }
};

export default cors(connectDb(handler));
