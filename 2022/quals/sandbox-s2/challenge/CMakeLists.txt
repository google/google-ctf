# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.13)

project(sandbox_s2 CXX)

include(FetchContent)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

FetchContent_Declare(SandboxedAPI
  GIT_REPOSITORY https://github.com/google/sandboxed-api.git
  GIT_TAG        5e61ce08533af4b066970a7452254ecfc0f48d50
)
FetchContent_MakeAvailable(SandboxedAPI)

add_executable(chal
  chal.cc
)

target_link_libraries(chal
  PRIVATE sapi::sapi
          absl::strings
)
