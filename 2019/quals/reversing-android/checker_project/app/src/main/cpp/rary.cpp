// Copyright 2019 Google LLC
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//   https://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <jni.h>
#include <string.h>
#include <stdlib.h>

int d[] = {0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0,
                   0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0,
                   0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0};
int p = 0;
int c = 0;

void M(char* arr, int len) {
    if (len <= 1) {
        return;
    }
    int len1 = len / 2;
    int len2 = len - len1;
    char* l = arr;
    char* r = arr + len1;

    M(arr, len1);
    if (!c) {
        return;
    }
    M(r, len2);
    if (!c) {
        return;
    }

    int i = 0, j = 0, k = 0;
    char temp[16];

    while (i < len1 && j < len2) {
        if (l[i] < r[j]) {
            if (d[p] != 1) {
                c = 0;
                return;
            }
            ++p;

            temp[k] = l[i];
            ++i;
        } else if (l[i] > r[j]) {
            if (d[p] != 0) {
                c = 0;
                return;
            }
            ++p;

            temp[k] = r[j];
            ++j;
        } else {
            c = 0;
            return;
        }
        ++k;
    }
    while (i < len1) {
        temp[k] = l[i];
        ++i;
        ++k;
    }
    while (j < len2) {
        temp[k] = r[j];
        ++j;
        ++k;
    }
    memcpy(arr, temp, len);
}

bool C(char* key) {
    char sum[16];
    for (int i = 0; i < 16; ++i) {
        sum[i] = key[2 * i] + key[2 * i + 1];
    }

    c = 1;
    p = 0;
    M(sum, 16);
    return sum[15] < 16 && c;
}

extern "C"
JNIEXPORT jboolean JNICALL Java_com_google_ctf_game_Checker_nativeCheck(
        JNIEnv *env, jobject /* this */, jbyteArray key) {
    jsize len = env->GetArrayLength(key);
    if (len != 32) {
        return false;
    }
    jbyte* jbyte_arr= env->GetByteArrayElements(key, 0);
    char native_arr[32];
    for (int i = 0; i < len; ++i) {
        native_arr[i] = jbyte_arr[i];
    }
    return C(native_arr);
}
