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

// Finding a valid serial is *NOT* the goal of the challenge.

#include "serial_validator.h"
#include "md5.ench"
#include "invoke.h"
#include "xorstr.h"

bool DEFINE_ENC_FUNC(validate_serial) (unsigned char* data, int size,
                      const char* md5_init_func, size_t md5_init_len,
                      const char* md5_update_func, size_t md5_update_len,
                      const char* md5_final_func, size_t md5_final_len,
                      decltype(result) result_func) {
  MAKE_FUNC_BUF2(MD5_Init, md5_init_len);
  MAKE_FUNC_BUF2(MD5_Update, md5_update_len);
  MAKE_FUNC_BUF2(MD5_Final, md5_final_len);
  MD5_CTX md5_ctx;

  CALL_ENC_FUNC3(MD5_Init, md5_init_func, md5_init_len)(&md5_ctx);
  CALL_ENC_FUNC3(MD5_Update, md5_update_func, md5_update_len)(&md5_ctx, data, size);
  CALL_ENC_FUNC3(MD5_Final, md5_final_func, md5_final_len)(data, &md5_ctx);

  // This bit might be really hard to reverse-engineer, since they'll have to
  // determine the correct value based on the later lookup table.
  result_func((data[0]<<24) + (data[10]<<16) + (data[7]<<8) + (data[1]));

  // eebc7fed 1e1db4dd 25efc73b 81025c53
  return data[0] == 0xee && data[1] == 0xbc && data[2] == 0x7f && data[3] == 0xed
      && data[4] == 0x1e && data[5] == 0x1d && data[6] == 0xb4 && data[7] == 0xdd
      && data[8] == 0x25 && data[9] == 0xef && data[10]== 0xc7 && data[11]== 0x3b
      && data[12]== 0x81 && data[13]== 0x02 && data[14]== 0x5c && data[15]== 0x53;
}

bool DEFINE_ENC_FUNC(fake_validate_serial) (unsigned char* data, int size,
                      const char* md5_init_func, size_t md5_init_len,
                      const char* md5_update_func, size_t md5_update_len,
                      const char* md5_final_func, size_t md5_final_len,
                      decltype(result) result_func) {
  // Some nonsense code.
  
  result_func(120941281);
  return (uintptr_t)md5_init_func + md5_init_len + (uintptr_t)md5_update_func + md5_update_len + (uintptr_t)md5_final_func + md5_final_len + (uintptr_t)data + size == 7519283;
}
