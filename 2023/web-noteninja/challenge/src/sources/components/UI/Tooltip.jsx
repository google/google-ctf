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

import React, { useState } from "react";

const Tooltip = ({ text, children, position, noBg, onClick, color }) => {
  const [isVisible, setIsVisible] = useState(false);

  const handleMouseEnter = () => {
    setIsVisible(true);
  };

  const handleMouseLeave = () => {
    setIsVisible(false);
  };

  return (
    <div
      className={`relative flex justify-center w-fit cursor-pointer duration-300 p-2`}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
      onClick={onClick}
    >
      {children}
      {isVisible && (
        <div
          className={`bg-[#333] text-[#fff] py-[6px] px-[4px] rounded-[4px] absolute z-1 text-[12px] break-words w-[150px] max-w-max`}
          style={{
            [position[0]]: position[1],
            color: color || "white",
          }}
        >
          {text}
        </div>
      )}
    </div>
  );
};

export default Tooltip;