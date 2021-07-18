// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef BOT_XORTOOL_H
#define BOT_XORTOOL_H

#include <string>

struct obf_str_t {
    const char* data;
    size_t length;
};
// -1 as we don't need the terminating null.
#define NEW_OBF_STR(X) {.data = X, .length = sizeof(X) - 1}

std::string DoXor (const char* ciphertext, int len);
#define DEOBFUSCATE(X) (DoXor(X->data, X->length).c_str())

#endif //BOT_XORTOOL_H
