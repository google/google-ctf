// Copyright 2024 Google LLC
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

#version 410

uniform sampler2D tex;

in FragData {
    vec2 uv;
    float spriteAlpha;
    flat uint flashing;
} inData;

out vec4 f_color;

const float eps = 0.000001;

void main() {
    vec2 texel_size = vec2(1,1) / textureSize(tex, 0);
    vec4 texel = texture(tex, inData.uv + texel_size/2);
    if(inData.flashing == 1) {
        if(texel.a > 0) {
            f_color = vec4(1, 1, 1, 1);
        } else {
            discard;
        }
    } else {
        f_color = inData.spriteAlpha * texel;
    }
}
