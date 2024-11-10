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

in vec4 in_rect;
in vec4 in_color;
in float in_borderWidth;
in int in_flags;

out PointData {
    vec2 tr;
    vec4 color;
    float borderWidth;
    int flags;
} outData;

void main() {
    gl_Position = vec4(in_rect.xy, 0.0, 1.0);
    outData.tr = in_rect.zw;
    outData.color = in_color;
    outData.borderWidth = in_borderWidth;
    outData.flags = in_flags;
}
