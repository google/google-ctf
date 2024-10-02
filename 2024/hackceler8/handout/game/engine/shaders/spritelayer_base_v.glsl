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

#version 450

in vec2 in_pos;
in float in_alpha;
in float in_scale;
in int in_idx;
in int in_flashing;

out PointData {
    vec2 size;
    // BottomLeft, TopRight
    vec2 uvBL;
    vec2 uvTR;
    float alpha;
    float scale;
    uint flashing;
} outData;

struct BufData {
    vec2 size;
    vec2 uvBL;
    vec2 uvTR;
};

layout(binding = 2, std430) readonly buffer texSSBO {
    BufData texData[];
};

void main() {
    gl_Position = vec4(in_pos, 0.0, 1.0);
    BufData d = texData[in_idx];
    outData.size = d.size;
    outData.uvBL = d.uvBL;
    outData.uvTR = d.uvTR;
    outData.alpha = in_alpha;
    outData.scale = in_scale;
    outData.flashing = in_flashing;
}
