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

layout (points) in;
layout (triangle_strip, max_vertices=8) out;

uniform Projection {
    uniform mat4 matrix;
} proj;

uniform float hitboxWidth;

in PointData {
    vec2 size;
    vec2 uvBL;
    vec2 uvTR;
    float alpha;
    float scale;
    uint flashing;
} inData[];

out FragData {
    vec2 uv;
    float spriteAlpha;
    flat uint flashing;
} outData;

const float eps = 0.000001;

void main() {
    ////////  main sprite //////
    if(inData[0].alpha > eps) {
        vec2 base_sz = inData[0].size * inData[0].scale;
        vec4 base_pos = gl_in[0].gl_Position;
        base_pos.xy -= base_sz/2;
        vec2 tex_sz = inData[0].uvTR - inData[0].uvBL;
        float alpha = inData[0].alpha;

        gl_Position= proj.matrix * vec4(base_pos.xy + vec2(0,0), base_pos.zw);
        outData.uv = inData[0].uvBL;
        outData.spriteAlpha = alpha;
        outData.flashing = inData[0].flashing;
        EmitVertex();
        gl_Position= proj.matrix * vec4(base_pos.xy + vec2(base_sz.x, 0), base_pos.zw);
        outData.uv = inData[0].uvBL + vec2(tex_sz.x, 0);
        outData.spriteAlpha = alpha;
        outData.flashing = inData[0].flashing;
        EmitVertex();
        gl_Position= proj.matrix * vec4(base_pos.xy + vec2(0,base_sz.y), base_pos.zw);
        outData.uv = inData[0].uvBL + vec2(0, tex_sz.y);
        outData.spriteAlpha = alpha;
        outData.flashing = inData[0].flashing;
        EmitVertex();
        gl_Position= proj.matrix * vec4(base_pos.xy + base_sz, base_pos.zw);
        outData.uv = inData[0].uvTR;
        outData.spriteAlpha = alpha;
        outData.flashing = inData[0].flashing;
        EmitVertex();

        EndPrimitive();
    }
}
