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

struct TransferHeader {
    // device sends 1 back after it fully read the chunk. Otherwise expect 55
    unsigned char acknowledged;
    // # of this block (detecting new chunk)
    unsigned char index;
    // end block index, if index == end_index, jump to shellcode afterwards.
    unsigned char end_index;
    // size of this chunk
    unsigned char size;

    char data[0];
} __attribute__((packed));

