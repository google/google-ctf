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

import React from "react";
import Navbar from "./Navbar";
import Alert from "./Alert";
import NotesProvider from "@/sources/context/NotesContext";
import Script from "next/script";
import { Roboto } from "next/font/google";

const font = Roboto({
  subsets: ["latin"],
  weight: ["100", "300", "400", "700", "900"],
});

const Layout = ({ children }) => {
  return (
    <div className={font.className}>
      <Script
        src={`https://www.google.com/recaptcha/api.js?render=${process.env.NEXT_PUBLIC_RECAPTCHA_SITE_KEY}`}
      ></Script>
      <NotesProvider>
        <Navbar />
        <Alert />
        {children}
      </NotesProvider>
    </div>
  );
};

export default Layout;
