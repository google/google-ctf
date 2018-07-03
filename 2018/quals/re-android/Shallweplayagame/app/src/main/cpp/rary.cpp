/*
 * Copyright 2018 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <functional>
#include <jni.h>
#include <string.h>
#include <android/log.h>

static JNIEnv *env;
static bool initialized = false;

const char* decryptString(uint8_t *payload, volatile int length) {
    // volatile is used to remove some of the compiler optimizations so it's slightly more readable
    for (volatile int i = 1; i < length; ++i) {
        payload[i] = (uint8_t) (payload[i - 1] + payload[i]);
    }
    return reinterpret_cast<const char*>(payload);
}

// Yes, these were encrypted by hand, but a real obfuscator can easily
// automatize this process.
uint8_t kClassEnc0[] = {106, 247, 21, 235, 23, 183, 52, 15, 7, 247, 4, 251, 192, 20, 38, 7, 248,
                        253, 13, 142};
uint8_t kClassEnc1[] = {106, 247, 21, 235, 23, 183, 52, 15, 7, 247, 4, 251, 192, 68, 253, 245, 254,
                        204, 36, 18, 254, 15, 243, 15, 215, 26, 20, 218, 29, 245, 254, 157};
uint8_t kClassEnc2[] = {106, 247, 21, 235, 206, 68, 242, 254, 18, 253, 247, 11, 5, 182, 30, 24, 14,
                        0, 238, 6, 254, 223, 37, 254, 254, 14, 1, 140};
uint8_t kClassEnc3[] = {106, 247, 21, 235, 206, 70, 255, 245, 3, 195, 35, 15, 13, 246, 11, 254,
                        147};
uint8_t kMethodNameEnc0[] = {103, 254, 15, 213, 37, 5, 1, 237, 13, 245, 2, 155};
uint8_t kMethodNameEnc1[] = {60, 45, 5, 251, 11, 202, 194};
uint8_t kMethodNameEnc2[] = {105, 5, 251, 11, 140};
uint8_t kMethodNameEnc3[] = {100, 11, 215, 35, 5, 243, 11, 148};
uint8_t kMethodNameEnc4[] = {103, 254, 15, 213, 37, 5, 1, 237, 13, 245, 2, 155};
uint8_t kMethodNameEnc5[] = {117, 251, 244, 253, 19, 241, 155};
uint8_t kMethodNameEnc6[] = {100, 5, 254, 254, 14, 1, 140};
uint8_t kMethodNameEnc7[] = {60, 45, 5, 251, 11, 202, 194};
uint8_t kMethodNameEnc8[] = {110, 247, 19, 252, 206, 55, 251, 241, 14, 141};
uint8_t kMethodSigEnc0[] = {40, 36, 30, 247, 21, 235, 206, 61, 245, 13, 249, 200, 36, 33, 254, 247,
                            5, 249, 212, 238, 35, 30, 247, 21, 235, 23, 183, 52, 15, 7, 247, 4, 251,
                            192, 20, 38, 7, 248, 253, 13, 201, 197};
uint8_t kMethodSigEnc1[] = {40, 51, 231, 10, 30, 247, 21, 235, 206, 61, 245, 13, 249, 200, 36, 33,
                            254, 247, 5, 249, 212, 238, 45, 170};
uint8_t kMethodSigEnc2[] = {40, 33, 3, 30, 247, 21, 235, 206, 68, 242, 254, 18, 253, 247, 11, 5,
                            182, 28, 26, 20, 194, 238, 45, 170};
uint8_t kMethodSigEnc3[] = {40, 51, 231, 231, 50, 231, 190};
uint8_t kMethodSigEnc4[] = {40, 36, 30, 247, 21, 235, 206, 61, 245, 13, 249, 200, 36, 33, 254, 247,
                            5, 249, 212, 238, 35, 30, 247, 21, 235, 206, 68, 242, 254, 18, 253, 247,
                            11, 5, 182, 30, 24, 14, 0, 238, 6, 254, 223, 37, 254, 254, 14, 1, 199,
                            197};
uint8_t kMethodSigEnc5[] = {40, 51, 231, 231, 45, 170};
uint8_t kMethodSigEnc6[] = {40, 1, 50, 231, 190};
uint8_t kMethodSigEnc7[] = {40, 34, 223, 45, 170};
uint8_t kMethodSigEnc8[] = {40, 51, 231, 231, 45, 170};
uint8_t kStringEnc0[] = {65, 4, 14, 220, 22, 254, 255, 237, 31, 33, 225, 17, 3, 0, 5, 5, 249, 153};
uint8_t kStringEnc1[] = {65, 4, 14, 173};
uint8_t kStringEnc2[] = {83, 245, 249, 236, 5, 3, 1, 202};

const char* kClassMap[4];
const char* kMethodNameMap[9];
const char* kMethodSigMap[9];
const char* kStringMap[3];

enum MethodTypes { METHOD, STATIC_METHOD };

struct MethodMetadata {
    jmethodID id;
    int method_index;
    int type_index;
    int caller_index;
    int argc;
};

void initialize() {
    // javax/crypto/Cipher = 0
    kClassMap[0] = decryptString(kClassEnc0, 20);
    // javax/crypto/spec/SecretKeySpec = 1
    kClassMap[1] = decryptString(kClassEnc1, 32);
    // java/security/MessageDigest = 2
    kClassMap[2] = decryptString(kClassEnc2, 28);
    // java/util/Random = 3
    kClassMap[3] = decryptString(kClassEnc3, 17);

    // getInstance = 0
    kMethodNameMap[0] = decryptString(kMethodNameEnc0, 12);
    // <init> = 1
    kMethodNameMap[1] = decryptString(kMethodNameEnc1, 7);
    // init = 2
    kMethodNameMap[2] = decryptString(kMethodNameEnc2, 5);
    // doFinal = 3
    kMethodNameMap[3] = decryptString(kMethodNameEnc3, 8);
    // getInstance = 4
    kMethodNameMap[4] = decryptString(kMethodNameEnc4, 12);
    // update = 5
    kMethodNameMap[5] = decryptString(kMethodNameEnc5, 7);
    // digest = 6
    kMethodNameMap[6] = decryptString(kMethodNameEnc6, 7);
    // <init> = 7
    kMethodNameMap[7] = decryptString(kMethodNameEnc7, 7);
    // nextBytes = 8
    kMethodNameMap[8] = decryptString(kMethodNameEnc8, 10);

    // (Ljava/lang/String;)Ljavax/crypto/Cipher; for Cipher.getInstance
    kMethodSigMap[0] = decryptString(kMethodSigEnc0, 42);
    // ([BLjava/lang/String;)V for SecretKeySpec.<init>
    kMethodSigMap[1] = decryptString(kMethodSigEnc1, 24);
    // (ILjava/security/Key;)V for Cipher.init
    kMethodSigMap[2] = decryptString(kMethodSigEnc2, 24);
    // ([B)[B for Cipher.doFinal
    kMethodSigMap[3] = decryptString(kMethodSigEnc3, 7);
    // (Ljava/lang/String;)Ljava/security/MessageDigest; for MessageDigest.getInstance
    kMethodSigMap[4] = decryptString(kMethodSigEnc4, 50);
    // ([B)V for MessageDigest.update
    kMethodSigMap[5] = decryptString(kMethodSigEnc5, 6);
    // ()[B for MessageDigest.digest
    kMethodSigMap[6] = decryptString(kMethodSigEnc6, 5);
    // (J)V for Random.<init>
    kMethodSigMap[7] = decryptString(kMethodSigEnc7, 5);
    // ([B)V for Random.nextBytes
    kMethodSigMap[8] = decryptString(kMethodSigEnc8, 6);

    // AES/ECB/NoPadding
    kStringMap[0] = decryptString(kStringEnc0, 18);
    // AES
    kStringMap[1] = decryptString(kStringEnc1, 4);
    // SHA-256
    kStringMap[2] = decryptString(kStringEnc2, 8);
}

int Int(jobject value) {
    jclass int_class = env->FindClass("java/lang/Integer");
    if (int_class == NULL) { return 0; }
    jmethodID get_val_method = env->GetMethodID(int_class, "intValue", "()I");
    if (get_val_method == NULL) { return 0; }
    return env->CallIntMethod(value, get_val_method);
}

long Long(jobject value) {
    jclass long_class = env->FindClass("java/lang/Long");
    if (long_class == NULL) { return 0; }
    jmethodID get_val_method = env->GetMethodID(long_class, "longValue", "()J");
    if (get_val_method == NULL) { return 0; }
    return env->CallLongMethod(value, get_val_method);
}

jobject String(jobject value) {
    int string_index = Int(value);
    return env->NewStringUTF(kStringMap[string_index]);
}

jobject Nop(jobject value) {
    return value;
}

int IntArray(jobject value,
             int index) {
    jintArray *int_arr = reinterpret_cast<jintArray*>(&value);
    jint *ints = env->GetIntArrayElements(*int_arr, NULL);
    return static_cast<int>(ints[index]);
}

// DON'T DO THIS AT HOME
#define CALL_METHOD0(F, c, m) F(c, m)
#define CALL_METHOD1(F, c, m, h, o) F(c, m, h[0](o[0]))
#define CALL_METHOD2(F, c, m, h, o) F(c, m, h[0](o[0]), h[1](o[1]))
#define CALL_METHOD3(F, c, m, h, o) F(c, m, h[0](o[0]), h[1](o[1]), h[2](o[2]))
#define CALL_METHOD4(F, c, m, h, o) F(c, m, h[0](o[0]), h[1](o[1]), h[2](o[2]), h[3](o[3]))
#define CALL_METHOD(N, F, c, m, h, o)                   \
    switch(N) {                                         \
        case 1: { CALL_METHOD1(F, c, m, h, o); break; } \
        case 2: { CALL_METHOD2(F, c, m, h, o); break; } \
        case 3: { CALL_METHOD3(F, c, m, h, o); break; } \
        case 4: { CALL_METHOD4(F, c, m, h, o); break; } \
        case 0: /* fallthrough */                       \
        default: { CALL_METHOD0(F, c, m); break; }      \
    }
#define RET_METHOD(N, F, c, m, h, o)                    \
    switch(N) {                                         \
        case 1: { return CALL_METHOD1(F, c, m, h, o); } \
        case 2: { return CALL_METHOD2(F, c, m, h, o); } \
        case 3: { return CALL_METHOD3(F, c, m, h, o); } \
        case 4: { return CALL_METHOD4(F, c, m, h, o); } \
        case 0: /* fallthrough */                       \
        default: { return CALL_METHOD0(F, c, m); }      \
    }

typedef void* (*Handler)(jobject);

void PrepareArgs(MethodMetadata method,
                 jobjectArray *args,
                 Handler arg_handlers[],
                 jobject arg_objects[]) {
    const char *arg_type = kMethodSigMap[method.method_index];
    arg_type++;

    for (int i = 0; i < method.argc; ++i) {
        jobject obj = env->GetObjectArrayElement(*args, i);
        arg_objects[i] = obj;

        switch (*arg_type) {
            case '[': {
                ++arg_type;
                if (*arg_type == 'L') {
                    while (*++arg_type != ';');
                } else {
                    ++arg_type;
                }
                arg_handlers[i] = (Handler) (&Nop);  // Undefined behavior, sorry compiler.
                break;
            }
            case 'L': {
                if (!strncmp(arg_type, "Ljava/lang/String;", 18)) {
                    arg_handlers[i] = (Handler) (&String);  // And here...
                } else {
                    arg_handlers[i] = (Handler) (&Nop);  // And here...
                }
                while (*++arg_type != ';');
                break;
            }
            case 'I': {
                ++arg_type;
                arg_handlers[i] = (Handler) (&Int);  // And here...
                break;
            }
            case 'J': {
                ++arg_type;
                arg_handlers[i] = (Handler) (&Long);  // And here...
                break;
            }
            default: {
                // __android_log_write(ANDROID_LOG_INFO, "ctf", "Unhandled parameter type.");
                break;
            }
        }
    }
}

jobject CallMethod(jclass cls,
                   jobject obj,
                   MethodMetadata method,
                   jobjectArray *args) {

    // Prepare args
    Handler arg_handlers[method.argc];
    jobject arg_objects[method.argc];
    PrepareArgs(method, args, arg_handlers, arg_objects);

    switch (method.caller_index) {
        case 0: RET_METHOD(method.argc, env->CallObjectMethod, obj, method.id,
                           arg_handlers, arg_objects);
        case 2: RET_METHOD(method.argc, env->NewObject, cls, method.id,
                           arg_handlers, arg_objects);
        case 1: CALL_METHOD(method.argc, env->CallVoidMethod, obj, method.id,
                            arg_handlers, arg_objects);  // fallthrough
        default: return NULL;
    }
}

jobject CallStaticMethod(jclass cls,
                         MethodMetadata method,
                         jobjectArray *args) {
    // Prepare args
    Handler arg_handlers[method.argc];
    jobject arg_objects[method.argc];
    PrepareArgs(method, args, arg_handlers, arg_objects);

    switch (method.caller_index) {
        case 0: RET_METHOD(method.argc, env->CallStaticObjectMethod, cls, method.id,
                           arg_handlers, arg_objects);
        case 1: CALL_METHOD(method.argc, env->CallStaticVoidMethod, cls, method.id,
                            arg_handlers, arg_objects);  // fallthrough
        default: return NULL;
    }
}

extern "C"
JNIEXPORT jobject
JNICALL
Java_com_google_ctf_shallweplayagame_N__1(
        JNIEnv *jni_env,
        jobject /* this */,
        jobjectArray args) {
    if (!initialized) {
        initialize();
        initialized = true;
    }

    env = jni_env;

    // Find class
    jobject class_index = env->GetObjectArrayElement(args, 0);
    int class_index_ = Int(class_index);
    jclass cls = env->FindClass(kClassMap[class_index_]);

    // Find method parameters
    jobject method_args = env->GetObjectArrayElement(args, 1);
    MethodMetadata method_meta;
    method_meta.method_index = IntArray(method_args, 0);
    method_meta.type_index = IntArray(method_args, 1);
    method_meta.caller_index = IntArray(method_args, 2);

    // Prepare real args list
    jclass object_class = env->FindClass("java/lang/Object");
    jsize argc = env->GetArrayLength(args);
    int base_args = 2;
    if (method_meta.type_index == METHOD && method_meta.caller_index != 2) {
        base_args++;
    }
    method_meta.argc = argc - base_args;

    jobjectArray real_args = env->NewObjectArray(method_meta.argc, object_class, NULL);
    for (int i = 0; i < method_meta.argc; ++ i) {
        jobject arg = env->GetObjectArrayElement(args, i + base_args);
        env->SetObjectArrayElement(real_args, i, arg);
    }

    // Execute method
    if (method_meta.type_index == METHOD) {
        method_meta.id = env->GetMethodID(
                cls, kMethodNameMap[method_meta.method_index],
                kMethodSigMap[method_meta.method_index]);
        jobject obj = env->GetObjectArrayElement(args, 2);
        return CallMethod(cls, obj, method_meta, &real_args);

    } else if (method_meta.type_index == STATIC_METHOD) {
        method_meta.id = env->GetStaticMethodID(
                cls, kMethodNameMap[method_meta.method_index],
                kMethodSigMap[method_meta.method_index]);
        return CallStaticMethod(cls, method_meta, &real_args);
    }
    return NULL;
}
