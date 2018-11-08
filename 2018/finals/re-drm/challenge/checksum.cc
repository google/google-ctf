// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Author: Ian Eldred Pudney

#include "checksum.h"
#include "md5.ench"
#include "invoke.h"

unsigned long long DEFINE_ENC_FUNC(checksum) (unsigned char* data, unsigned char* data_end,
                      const char* md5_init_func, size_t md5_init_len,
                      const char* md5_update_func, size_t md5_update_len,
                      const char* md5_final_func, size_t md5_final_len) {
  MAKE_FUNC_BUF2(MD5_Init, md5_init_len);
  MAKE_FUNC_BUF2(MD5_Update, md5_update_len);
  MAKE_FUNC_BUF2(MD5_Final, md5_final_len);
  MD5_CTX md5_ctx;

  CALL_ENC_FUNC3(MD5_Init, md5_init_func, md5_init_len)(&md5_ctx);
  CALL_ENC_FUNC3(MD5_Update, md5_update_func, md5_update_len)(&md5_ctx, data, data_end - data);
  unsigned char result[64];
  CALL_ENC_FUNC3(MD5_Final, md5_final_func, md5_final_len)(result, &md5_ctx);
  return *(unsigned long long*)result;
}
