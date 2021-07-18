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
//
// Created by kotov on 6/14/21.
//

#include <jni.h>

#include "CryptoTool.h"
#include "XorTool.h"

#define ENCRYPT_MODE 1
#define DECRYPT_MODE 2

constexpr char kAesKey[] = "eaW~IFhnvlIoneLl";
constexpr char kRsaKey[] = "\x30\x81\x9f\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05"
                           "\x00\x03\x81\x8d\x00\x30\x81\x89\x02\x81\x81\x00\xb0\x01\xbf\x31\xdb"
                           "\xc6\xa2\x47\xca\xcc\xa8\xd2\x79\x55\x07\x20\xa0\xbf\x93\x57\x43\x5e"
                           "\x46\x55\x2c\x65\xe5\x36\xce\x71\x7a\xb6\x09\x9d\x4a\xaf\xc7\x9f\xfd"
                           "\x19\xe4\x64\x44\x84\x6b\x76\x13\x36\x8e\xd6\xbf\x47\x86\x71\x33\x69"
                           "\x1f\x35\xea\xb8\xe9\xe5\x36\x88\x22\xee\xcc\x73\xc4\x00\xd8\x27\x22"
                           "\xa8\xf3\x96\xd2\x21\xfe\xfe\x45\x54\x37\xfa\x4b\x59\xb0\x64\x5c\xeb"
                           "\x5d\x1e\x42\xdd\x97\xeb\xa8\x18\x2b\x37\x44\x52\xaf\xc4\x1a\xc1\x9b"
                           "\xb4\x59\xb0\xd0\x2d\xbc\xd5\xe9\x3b\x7c\xfb\x50\xcc\xe8\xa8\xae\x4d"
                           "\xdd\x06\xc1\x77\x02\x03\x01\x00\x01";

// constexpr char kAes[] = "AES";
struct obf_str_t str_aes = NEW_OBF_STR("\x22\x03\x06");
#define kAes DEOBFUSCATE((&str_aes))

// constexpr char kRsa[] = "RSA";
struct obf_str_t str_rsa = NEW_OBF_STR("\x31\x15\x14");
#define kRsa DEOBFUSCATE((&str_rsa))

//constexpr char kSecretKeySpecPath[] = "javax/crypto/spec/SecretKeySpec";
struct obf_str_t str_secret_key_spec_path = NEW_OBF_STR(
        "\x09\x27\x23\x06\x1c\x78\x5a\x28\x30\x37\x22\x5d\x4e\x26\x13\x02\x3a\x78\x66\x10\x01"
        "\x42\x06\x13\x28\x08\x2f\x61\x2a\x30\x57");
#define kSecretKeySpecPath DEOBFUSCATE((&str_secret_key_spec_path))

//constexpr char kCipherPath[] = "javax/crypto/Cipher";
struct obf_str_t str_cipher_path = NEW_OBF_STR(
        "\x09\x27\x23\x06\x1c\x78\x5a\x28\x30\x37\x22\x5d\x4e\x16\x0a\x17\x31\x32\x47");
#define kCipherPath DEOBFUSCATE((&str_cipher_path))

//constexpr char kConstructor[] = "<init>";
struct obf_str_t str_constructor = NEW_OBF_STR("\x5f\x2f\x3b\x0e\x10\x69");
#define kConstructor DEOBFUSCATE((&str_constructor))

//constexpr char kGetInstance[] = "getInstance";
struct obf_str_t str_get_instance = NEW_OBF_STR("\x04\x23\x21\x2e\x0a\x24\x4d\x3b\x27\x24\x33");
#define kGetInstance DEOBFUSCATE((&str_get_instance))

//constexpr char kInit[] = "init";
struct obf_str_t str_init = NEW_OBF_STR( "\x0a\x28\x3c\x13");
#define kInit DEOBFUSCATE((&str_init))

//constexpr char kDoFinal[] = "doFinal";
struct obf_str_t str_do_final = NEW_OBF_STR("\x07\x29\x13\x0e\x0a\x36\x55");
#define kDoFinal DEOBFUSCATE((&str_do_final))

// char kX509SpecPath[] = "java/security/spec/X509EncodedKeySpec";
struct obf_str_t str_x509_spec_path = NEW_OBF_STR(
        "\x09\x27\x23\x06\x4b\x24\x5c\x39\x3c\x35\x3f\x46\x18\x7a\x10\x17\x3c\x34\x1a\x2d\x57"
        "\x00\x5a\x22\x0d\x0e\x39\x56\x3f\x31\x7f\x58\x1a\x15\x25\x02\x07");
#define kX509SpecPath DEOBFUSCATE((&str_x509_spec_path))

// char kKeyFactoryPath[] = "java/security/KeyFactory";
struct obf_str_t str_key_factory_path = NEW_OBF_STR(
        "\x09\x27\x23\x06\x4b\x24\x5c\x39\x3c\x35\x3f\x46\x18\x7a\x28\x02\x20\x11\x54\x16\x16\x5f\x11\x1e");
#define kKeyFactoryPath DEOBFUSCATE((&str_key_factory_path))

// char kGeneratePublic[] = "generatePublic";
struct obf_str_t str_generate_public = NEW_OBF_STR(
        "\x04\x23\x3b\x02\x16\x36\x4d\x3f\x19\x32\x34\x5e\x08\x36");
#define kGeneratePublic DEOBFUSCATE((&str_generate_public))



// "([BLjava/lang/String;)V"
struct obf_str_t str_SecretKeySpecSig = NEW_OBF_STR(
        "\x4b\x1d\x17\x2b\x0e\x36\x4f\x3b\x66\x2b\x37\x5c\x06\x7a\x30\x13\x2b\x3e\x5b\x12\x59\x19\x35");
// "(Ljava/lang/String;)Ljavax/crypto/Cipher;"
struct obf_str_t str_CipherGetInstanceSig = NEW_OBF_STR(
        "\x4b\x0a\x3f\x06\x12\x36\x16\x36\x28\x29\x31\x1d\x32\x21\x11\x0e\x37\x30\x0e\x5c\x2e"
        "\x5a\x02\x11\x02\x15\x79\x51\x28\x2c\x44\x49\x0c\x69\x16\x0e\x14\x3f\x5c\x28\x72");
// "(ILjava/security/Key;)V"
struct obf_str_t str_KeySig = NEW_OBF_STR(
        "\x4b\x0f\x19\x0d\x05\x21\x58\x75\x3a\x22\x35\x47\x13\x3c\x17\x1e\x76\x1c\x50\x0c\x59\x19\x35");
// "(Ljava/lang/String;)Ljava/security/KeyFactory;"
struct obf_str_t str_KeyFactorySig = NEW_OBF_STR(
        "\x4b\x0a\x3f\x06\x12\x36\x16\x36\x28\x29\x31\x1d\x32\x21\x11\x0e\x37\x30\x0e\x5c\x2e"
        "\x5a\x02\x11\x02\x42\x25\x57\x39\x20\x46\x54\x17\x3f\x7a\x2c\x01\x2e\x7f\x3b\x2a\x33\x39\x40\x18\x6e");
// "(Ljava/security/spec/KeySpec;)Ljava/security/PublicKey;"
struct obf_str_t str_PublicKeySig = NEW_OBF_STR(
        "\x4b\x0a\x3f\x06\x12\x36\x16\x29\x2c\x24\x23\x40\x08\x21\x1a\x48\x2a\x27\x50\x16\x4d\x7b"
        "\x06\x1e\x30\x1d\x33\x51\x61\x7c\x78\x57\x02\x30\x34\x48\x17\x32\x5a\x2f\x3b\x2e\x22\x4b"
        "\x4e\x05\x16\x05\x35\x3e\x56\x3e\x07\x49\x58");


jbyteArray GetKey(JNIEnv* env, const char* keystr, size_t keylen) {
    jbyteArray key = env->NewByteArray(keylen);
    env->SetByteArrayRegion(key, 0, keylen, (jbyte*)keystr);
    return key;
}

jobject GetKeySpec(JNIEnv* env) {
    jclass clazz = env->FindClass(kSecretKeySpecPath);
    if (clazz == nullptr) {
        return nullptr;
    }
    jmethodID mid = env->GetMethodID(clazz, kConstructor, DEOBFUSCATE((&str_SecretKeySpecSig)));
    if (mid == nullptr) {
        return nullptr;
    }
    jobject key_spec = env->NewObject(
            clazz, mid, GetKey(env, kAesKey, sizeof(kAesKey) -1), env->NewStringUTF(kAes));
    return key_spec;
}


jobject GetCipherAndInit(JNIEnv* env, int mode) {
    jclass class_cipher = env->FindClass(kCipherPath);
    if (class_cipher == nullptr) {
        return nullptr;
    }

    jmethodID mid_get_instance = env->GetStaticMethodID(
            class_cipher, kGetInstance, DEOBFUSCATE((&str_CipherGetInstanceSig)));
    if (mid_get_instance == nullptr) {
        return nullptr;
    }

    jobject cipher = env->CallStaticObjectMethod(
            class_cipher, mid_get_instance, env->NewStringUTF(kAes));
    if (cipher == nullptr) {
        return nullptr;
    }

    jmethodID mid_init = env->GetMethodID(class_cipher, kInit, DEOBFUSCATE((&str_KeySig)));
    if (mid_init == nullptr) {
        return nullptr;
    }

    env->CallVoidMethod(cipher, mid_init, mode, GetKeySpec(env));
    if (env->ExceptionCheck()) {
        return nullptr;
    }
    return cipher;
}

jbyteArray DoFinal(JNIEnv* env, jobject cipher, jbyteArray data) {
    jmethodID mid_do_final = env->GetMethodID(env->GetObjectClass(cipher), kDoFinal, "([B)[B");
    return reinterpret_cast<jbyteArray>(env->CallObjectMethod(cipher, mid_do_final, data));
}

jbyteArray RsaDecrypt(JNIEnv* env, jbyteArray ciphertext) {
    jclass class_x509 = env->FindClass(kX509SpecPath);
    if (class_x509 == nullptr) {
        return nullptr;
    }
    jmethodID mid_x509_cons = env->GetMethodID(class_x509, kConstructor, "([B)V");
    if (mid_x509_cons == nullptr) {
        return nullptr;
    }
    jobject keySpec = env->NewObject(
            class_x509, mid_x509_cons, GetKey(env, kRsaKey, sizeof(kRsaKey) - 1));

    if (keySpec == nullptr) {
        return nullptr;
    }

    jclass class_keyFactory = env->FindClass(kKeyFactoryPath);
    if (class_keyFactory == nullptr) {
        return nullptr;
    }

    jmethodID mid_getInstance = env->GetStaticMethodID(
            class_keyFactory, kGetInstance, DEOBFUSCATE((&str_KeyFactorySig)));

    if (mid_getInstance == nullptr) {
        return nullptr;
    }

    jobject keyFactory = env->CallStaticObjectMethod(
            class_keyFactory, mid_getInstance, env->NewStringUTF(kRsa));
    if (keyFactory == nullptr) {
        return nullptr;
    }

    jmethodID mid_generatePublic = env->GetMethodID(
            class_keyFactory, kGeneratePublic,
            DEOBFUSCATE((&str_PublicKeySig)));

    if (mid_generatePublic == nullptr) {
        return nullptr;
    }

    jobject publicKey = env->CallObjectMethod(keyFactory, mid_generatePublic, keySpec);
    if (publicKey == nullptr) {
        return nullptr;
    }

    jclass class_cipher = env->FindClass(kCipherPath);
    if (class_cipher == nullptr) {
        return nullptr;
    }

    jmethodID mid_get_instance = env->GetStaticMethodID(
            class_cipher, kGetInstance, DEOBFUSCATE((&str_CipherGetInstanceSig)));
    if (mid_get_instance == nullptr) {
        return nullptr;
    }

    jobject cipher = env->CallStaticObjectMethod(
            class_cipher, mid_get_instance, env->NewStringUTF(kRsa));
    if (cipher == nullptr) {
        return nullptr;
    }

    jmethodID mid_init = env->GetMethodID(class_cipher, kInit, DEOBFUSCATE((&str_KeySig)));
    if (mid_init == nullptr) {
        return nullptr;
    }

    env->CallVoidMethod(cipher, mid_init, 2, publicKey);
    if (env->ExceptionCheck()) {
        return nullptr;
    }

    return DoFinal(env, cipher, ciphertext);
}
