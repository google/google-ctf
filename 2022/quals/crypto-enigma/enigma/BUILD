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

# Author: Ian Eldred Pudney

cc_library(
    name = "plugboard",
    hdrs = ["plugboard.h"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "rotors",
    hdrs = ["rotors.h"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "reflector",
    hdrs = ["reflector.h"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "enigma",
    hdrs = ["enigma.h"],
    visibility = ["//visibility:public"],
    deps = [
        ":plugboard",
        ":reflector",
        ":rotors",
    ],
)

cc_binary(
    name = "machine",
    srcs = ["machine.cc"],
    visibility = ["//visibility:public"],
    deps = [":enigma"],
)
