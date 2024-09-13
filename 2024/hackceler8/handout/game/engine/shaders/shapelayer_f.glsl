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

const int f_CIRCLE_FILLED  = 1;
const int f_CIRCLE_OUTLINE = 3;
const int f_CIRCLE_FILLED_SOFT = 5;
const int f_RECTANGLE_FILLED  = 0;
const int f_RECTANGLE_OUTLINE = 2;

in FragData {
    vec4 fillColor;
    vec2 uv;
    flat float deform;
    flat float borderWidth;
    flat int flags;
} inData;

out vec4 f_color;

const float eps = 0.000001;

void main() {
    const vec2 center = vec2(0.5, 0.5);
    vec2 uv = inData.uv;
    float dis = distance(center, uv);
    if (inData.flags == f_CIRCLE_FILLED || inData.flags == f_CIRCLE_OUTLINE || inData.flags == f_CIRCLE_FILLED_SOFT) {
        if(dis > 0.5) {
            discard;
        }
        if (inData.flags == f_CIRCLE_OUTLINE) {
            if(dis < 0.5-inData.borderWidth) {
                discard;
            }
        }
        f_color = inData.fillColor;
        if (inData.flags == f_CIRCLE_FILLED_SOFT && dis > 0.1) f_color[3] = 2.5 * (0.5 - dis);
    } else {
        vec2 b = vec2(inData.borderWidth/inData.deform, inData.borderWidth);
        // if OUTLINE and zero border, we're drawing the outline with tris, skip the discard mechanism
        if (inData.flags == f_RECTANGLE_OUTLINE && inData.borderWidth > 0) {
            if ((b.x < uv.x && uv.x < 1-b.x) && (b.y < uv.y && uv.y < 1-b.y)) {
                discard;
            }
        }
        f_color = inData.fillColor;
    }
}
