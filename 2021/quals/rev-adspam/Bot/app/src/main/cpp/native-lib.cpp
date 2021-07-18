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

#include <android/log.h>
#include <jni.h>

#include <fstream>
#include <string>
#include <utility>

#include "CryptoTool.h"
#include "XorTool.h"

#define APPNAME "AdSpamBot"

// OBFUSCATED STRINGS
// "ad/spam/NativeAdapter"
struct obf_str_t ad_spam_MainActivity = NEW_OBF_STR(
        "\x02\x22\x7a\x14\x14\x36\x54\x75\x07\x26\x22\x5b\x17\x30\x22\x03\x38\x27\x41\x10\x10");
// "transform"
struct obf_str_t str_transform = NEW_OBF_STR("\x17\x34\x34\x09\x17\x31\x56\x28\x24");
// "oktorun"
struct obf_str_t str_oktorun = NEW_OBF_STR("\x0c\x2d\x21\x08\x16\x22\x57");
// "encrypt"
struct obf_str_t str_encrypt = NEW_OBF_STR("\x06\x28\x36\x15\x1d\x27\x4d");
// "decrypt"
struct obf_str_t str_decrypt = NEW_OBF_STR("\x07\x23\x36\x15\x1d\x27\x4d");
// "declicstr"
struct obf_str_t str_declicstr = NEW_OBF_STR("\x07\x23\x36\x0b\x0d\x34\x4a\x2e\x3b");
// "/proc/net/unix"
struct obf_str_t proc_net_unix = NEW_OBF_STR(
        "\x4c\x36\x27\x08\x07\x78\x57\x3f\x3d\x68\x23\x5c\x08\x2d");
// "frida.server"
struct obf_str_t frida_server = NEW_OBF_STR("\x05\x34\x3c\x03\x05\x79\x4a\x3f\x3b\x31\x33\x40");
// "/dev/socket/adbd"
struct obf_str_t dev_socket_adbd = NEW_OBF_STR(
        "\x4c\x22\x30\x11\x4b\x24\x56\x39\x22\x22\x22\x1d\x00\x31\x01\x03");


constexpr char str_constr_name[] = "<init>";

// HELPER FUNCTIONS

bool CheckProcNetUnix() {
    std::ifstream infile (DoXor(proc_net_unix.data, proc_net_unix.length));
    if (!infile.is_open()) {
        __android_log_print(
                ANDROID_LOG_VERBOSE, APPNAME,
                "Couldn't read /proc/net/unix");
        // TODO: should simply return true?
        return false;
    }
    std::string line;
    while(getline(infile, line)){
        if (line.find(DoXor(frida_server.data, frida_server.length)) != std::string::npos) {
            return false;
        }
    }
    infile.close();
    return true;
}


// EXPORTED FUNCTIONS
// Deobfuscate the byte array into a Java String.
static jstring transform(JNIEnv *env, jclass clazz, jbyteArray bytes) {
    jsize array_len = env->GetArrayLength(bytes);
    jbyte* data = env->GetByteArrayElements(bytes, 0);
    return env->NewStringUTF(DoXor(reinterpret_cast<const char*>(data), array_len).c_str());
}
// Anti-analysis checks.
static jboolean oktorun(JNIEnv *env, jclass clazz) {
    return CheckProcNetUnix();
}

// AES encryption / decryption
static jbyteArray EncryptDecrypt(JNIEnv *env, jclass clazz, jbyteArray cleartext, int mode) {
    jobject cipher = GetCipherAndInit(env, mode);
    if (cipher == nullptr) {
        __android_log_print(
                ANDROID_LOG_VERBOSE, APPNAME, "Couldn't get cipher.");
        return nullptr;
    }
    return DoFinal(env, cipher, cleartext);
}

static jbyteArray encrypt(JNIEnv *env, jclass clazz, jbyteArray cleartext) {
    return EncryptDecrypt(env, clazz, cleartext, 1);
}

static jbyteArray decrypt(JNIEnv *env, jclass clazz, jbyteArray ciphertext) {
    return EncryptDecrypt(env, clazz, ciphertext, 2);
}

static jbyteArray declicstr(JNIEnv* env, jclass clazz, jbyteArray str) {
    jbyteArray  res = RsaDecrypt(env, str);
    if (res == nullptr) {
        __android_log_print(
                ANDROID_LOG_VERBOSE, APPNAME, "Failed to decrypt license block.");
        return nullptr;
    }
    return res;
}

extern "C"
JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *pVoid) {

    JNIEnv* env;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    // Find your class. JNI_OnLoad is called from the correct class loader context for this to work.
    std::string my_class = DoXor(ad_spam_MainActivity.data, ad_spam_MainActivity.length);
    jclass c = env->FindClass(my_class.c_str());
    if (c == nullptr) {
        __android_log_print(
                ANDROID_LOG_VERBOSE, APPNAME, "Class %s not found.", my_class.c_str());
        return JNI_ERR;
    }

    static const JNINativeMethod methods[] = {
            {DEOBFUSCATE((&str_transform)),
             "([B)Ljava/lang/String;",
             reinterpret_cast<void*>(transform)},
            {DEOBFUSCATE((&str_oktorun)),
             "()Z",
             reinterpret_cast<void*>(oktorun)},
            {DEOBFUSCATE((&str_encrypt)),
             "([B)[B",
             reinterpret_cast<void*>(encrypt)},
            {DEOBFUSCATE((&str_decrypt)),
             "([B)[B",
             reinterpret_cast<void*>(decrypt)},
            {DEOBFUSCATE((&str_declicstr)),
             "([B)[B",
             reinterpret_cast<void*>(declicstr)},
    };
    int rc = env->RegisterNatives(c, methods, sizeof(methods)/sizeof(JNINativeMethod));
    if (rc != JNI_OK) {
        __android_log_print(
                ANDROID_LOG_VERBOSE, APPNAME, "RegisterNatives failed.");
        return rc;
    }

    return JNI_VERSION_1_6;
}
