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

const LoginBox = () => {
  const initial = {
    email: "",
    password: "",
  };
  const [form, setForm] = useState(initial);
  const { doFetch, setLogin } = useContext(NotesContext);

  const handleChange = (e) => {
    const name = e.target.name;
    const value = e.target.value;

    setForm((prev) => {
      const temp = { ...prev };
      temp[name] = value;
      return temp;
    });
  };

  const submitForm = async (token) => {
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

    if (!form.email || !form.password) {
      toast.error("Please enter credentials");
      return;
    }
    if (!emailRegex.test(form.email)) {
      toast.error("Invalid Email");
      return;
    }

    const response = await doFetch("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({
        email: form.email,
        password: form.password,
        captchaToken: token,
      }),
    });

    if (response.hasError) {
      toast.error(response.message);
    } else {
      setLogin({ isLoggedIn: true, data: response.data });
      setForm(initial);
      Router.push("/");
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
    <div className="flex flex-col items-center py-5">
      <div className="text-4xl font-bold">Access Account</div>

      <div className="mt-7 p-4 border-2 border-solid border-[#777777] flex flex-col gap-4 rounded-lg w-[400px]">
        <input
          className="appearance-none border border-[#848484] rounded w-[375px] p-3 "
          name="email"
          type="email"
          placeholder="Email"
          value={form.email}
          onChange={handleChange}
        />
        <input
          className="appearance-none border border-[#848484] rounded w-[375px] p-3 "
          name="password"
          type="password"
          placeholder="Password"
          value={form.password}
          onChange={handleChange}
        />
        <button
          type="submit"
          className="rounded w-full p-3 border-none cursor-pointer text-[16px] bg-[#3cc595] hover:bg-[#36ae84]"
          onClick={handleSubmit}
        >
          Login
        </button>
      </div>
    </div>
  );
};

export default LoginBox;
