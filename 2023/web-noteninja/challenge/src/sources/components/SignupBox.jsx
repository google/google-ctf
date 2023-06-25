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

import React, { useContext, useState } from "react";
import { toast } from "react-toastify";
import { NotesContext } from "../context/NotesContext";
import Router from "next/router";

const SignupBox = () => {
  const [form, setForm] = useState({
    name: "",
    email: "",
    password: "",
    cpassword: "",
  });
  const { doFetch } = useContext(NotesContext);

  const handleChange = (e) => {
    const name = e.target.name;
    const value = e.target.value;

    setForm((prev) => {
      const temp = { ...prev };
      temp[name] = value;
      return temp;
    });
  };

  const submitForm = async (captchatoken) => {
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

    if (!form.email || !form.password || !form.cpassword || !form.name) {
      toast.error("You can't leave required fields empty");
      return;
    }
    if (!emailRegex.test(form.email)) {
      toast.error("Invalid Email");
      return;
    }
    if (form.password !== form.cpassword) {
      toast.error("Incorrect Confirm Password");
      return;
    }

    const response = await doFetch("/api/auth/signup", {
      method: "POST",
      body: JSON.stringify({
        name: form.name,
        email: form.email,
        password: form.password,
        captchaToken: captchatoken,
      }),
    });

    if (response.hasError) {
      toast.error(response.message);
    } else {
      toast.success(response.message);
      Router.push("/login");
    }
  };

  const handleSubmit = async () => {
    grecaptcha.ready(function () {
      grecaptcha
        .execute(process.env.NEXT_PUBLIC_RECAPTCHA_SITE_KEY, {
          action: "submit",
        })
        .then(function (token) {
          submitForm(token);
        });
    });
  };

  return (
    <>
      <div className="flex flex-col items-center py-5">
        <div className="text-4xl font-bold">Create Account</div>

        <div className="mt-7 p-4 border-2 border-solid border-[#777777] flex flex-col gap-4 rounded-lg w-[400px]">
          <input
            className="appearance-none border border-solid border-[#848484] rounded p-3 w-[375px]"
            name="name"
            type="text"
            placeholder="Name"
            value={form.name}
            onChange={handleChange}
          />
          <input
            className="appearance-none border border-solid border-[#848484] rounded p-3 w-[375px]"
            name="email"
            type="email"
            placeholder="Email"
            value={form.email}
            onChange={handleChange}
          />
          <input
            className="appearance-none border border-solid border-[#848484] rounded p-3 w-[375px]"
            name="password"
            type="password"
            placeholder="Password"
            value={form.password}
            onChange={handleChange}
          />
          <input
            className="appearance-none border border-solid border-[#848484] rounded p-3 w-[375px]"
            name="cpassword"
            type="password"
            placeholder="Confirm Password"
            value={form.cpassword}
            onChange={handleChange}
          />
          <button
            type="submit"
            className="rounded w-full p-3 border-none text-[16px] bg-[#3cc595] hover:bg-[#36ae84]"
            onClick={handleSubmit}
          >
            Signup
          </button>
        </div>
      </div>
    </>
  );
};

export default SignupBox;
