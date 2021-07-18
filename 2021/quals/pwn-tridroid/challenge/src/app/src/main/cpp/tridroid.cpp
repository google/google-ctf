// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author: Sajjad "JJ" Arshad (sajjadium)

#include <jni.h>
#include <string>

#define DATA_MAX_SIZE 16

struct __attribute__((packed)) StackElement {
    char data[DATA_MAX_SIZE];
    StackElement *next;
};

StackElement *stack_top = nullptr;

void invokeJavaMethod(JNIEnv *env, jobject that, const char *methodName, const char *methodDesc) {
    jclass klass = env->GetObjectClass(that);
    jmethodID method = env->GetMethodID(klass, methodName, methodDesc);
    env->CallVoidMethod(that, method);
}

void push_element(const char *data) {
    StackElement *element = (StackElement *) malloc(sizeof(StackElement));
    memset(element->data, 0, DATA_MAX_SIZE);
    strncpy(element->data, data, DATA_MAX_SIZE);
    element->next = stack_top;

    stack_top = element;
}

void pop_element() {
    if (stack_top == nullptr) {
        return;
    }

    StackElement *old_stack_top = stack_top;
    stack_top = old_stack_top->next;
    free(old_stack_top);
}

void modify_element(JNIEnv *env, jbyteArray jdata) {
    if (stack_top == nullptr) {
        return;
    }

    char data[0x20];
    if (env->GetArrayLength(jdata) > 0) {
        memcpy(data, env->GetByteArrayElements(jdata, nullptr), env->GetArrayLength(jdata));
    }
    strcpy(stack_top->data, data);
}

const char *top_element() {
    if (stack_top == nullptr) {
        return "";
    }

    return stack_top->data;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_google_ctf_pwn_tridroid_MainActivity_manageStack__Ljava_lang_String_2_3B(JNIEnv *env,
                                                                                  jobject jthis,
                                                                                  jstring joperation,
                                                                                  jbyteArray jdata) {
    char content[60] = {0};
    const char *operation = env->GetStringUTFChars(joperation, nullptr);

    if (strcmp(operation, "push") == 0) {
        memcpy(content, (char *) env->GetByteArrayElements(jdata, nullptr),
               env->GetArrayLength(jdata));
        push_element(content);
    } else if (strcmp(operation, "pop") == 0) {
        pop_element();
    } else if (strcmp(operation, "modify") == 0) {
        modify_element(env, jdata);
    } else if (strcmp(operation, "top") == 0) {
        snprintf(content, sizeof(content), "%s", top_element());
        jbyteArray bytes = env->NewByteArray(strlen(content));
        env->SetByteArrayRegion(bytes, 0, strlen(content), (jbyte *) content);
        return bytes;
    }

    return env->NewByteArray(0);
}
