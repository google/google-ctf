// Copyright 2020 Google LLC
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
#include <cstddef>
#include <cstdint>
#include <cstdio>

#include <sys/mman.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <unistd.h>

bool read_into(char *buf, std::size_t to_read) {
  while(to_read) {
    ssize_t nread = read(0, buf, to_read);
    if(nread <= 0)
      return false;
    buf += nread;
    to_read -= nread;
  }
  return true;
}

char *read_data(int prot) {
  uint32_t len = 0;
  if(!read_into(reinterpret_cast<char*>(&len), sizeof(len)))
    return nullptr;

  std::size_t aligned_len = (len + 4096 - 1) & ~(4096 - 1);
  char *data = reinterpret_cast<char*>(mmap(nullptr, aligned_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  if(data == MAP_FAILED)
    return nullptr;
  if(!read_into(data, len))
    return nullptr;
  if(mprotect(data, aligned_len, prot) < 0)
    return nullptr;
  return data;
}

int main() {
  char *data = read_data(PROT_READ | PROT_WRITE);
  char *code = read_data(PROT_READ | PROT_EXEC);

  if(prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT))
    return -1;

  typedef int (*fptr)(char*);
  return reinterpret_cast<fptr>(code)(data);
}
