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

import FetchNotes from "@/sources/components/FetchNotes";
import Protector from "@/sources/components/Layout/Protector";

export default function Home() {
  return (
    <Protector>
      <div className="p-20 flex flex-col gap-5">
        <div className="text-4xl font-semibold">All Notes:</div>
        <FetchNotes />
      </div>
    </Protector>
  );
}
