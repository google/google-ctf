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

import { NotesContext } from "@/sources/context/NotesContext";
import Router from "next/router";
import { useContext } from "react";
import { toast } from "react-toastify";
import Loading from "../UI/Loading";

const Protector = ({ children }) => {
  const { login } = useContext(NotesContext);

  if (login.isLoggedIn === undefined) {
    return <Loading />;
  } else if (login.isLoggedIn === false) {
    Router.push("/login");
    return;
  }

  return <>{children}</>;
};

export default Protector;
