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
import { ImSpinner2 } from "react-icons/im";

const Loading = ({ height }) => {
  return (
    <div
      className={`flex items-center justify-center ${
        height ? height : "h-[80vh]"
      }`}
    >
      <ImSpinner2 className="animate-spin text-4xl" />
    </div>
  );
};

export default Loading;
