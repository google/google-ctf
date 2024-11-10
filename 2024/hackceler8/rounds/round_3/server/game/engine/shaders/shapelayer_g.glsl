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
layout (triangle_strip, max_vertices=16) out;

uniform Projection {
    uniform mat4 matrix;
} proj;

const int f_RECTANGLE_OUTLINE = 2;

in PointData {
    vec2 tr;
    vec4 color;
    float borderWidth;
    int flags;
} inData[];

out FragData {
    vec4 fillColor;
    vec2 uv;
    flat float deform;
    flat float borderWidth;
    flat int flags;
} outData;

const float eps = 0.000001;

void Emit(in vec4 pos, in vec2 uv, in float borderWidth, in float deform) {
    gl_Position = proj.matrix * pos;
    outData.uv = uv;
    outData.borderWidth = borderWidth;
    outData.flags = inData[0].flags;
    outData.fillColor = inData[0].color;
    outData.deform = deform;
    EmitVertex();
}

void main() {
    vec4 bl = vec4(gl_in[0].gl_Position.xy, 0, 1);
    vec4 tr = vec4(inData[0].tr, 0, 1);
    vec4 tl = vec4(bl.x, tr.y, 0, 1);
    vec4 br = vec4(tr.x, bl.y, 0, 1);
    vec4 sz = (tr - bl);
    float deform = sz.x/sz.y;

    // special case rectangle outlines, draw them with tris
    if(inData[0].flags == f_RECTANGLE_OUTLINE) {
        /*
            3 ----------- 5
            |\           /|
            | 4---------6 |
            | |         | |
            | |         | |
            | 2---------8 |
            |/           \|
            1 ----------- 7

            1 == 9 and 2 == 10 (overlapping)
            1 == hitboxBL; 5 == hitboxTR
        */
        vec4 sizeV = vec4(inData[0].borderWidth, inData[0].borderWidth, 0, 0);

        // not using any of the FS outline functionality here, just pass zeros
        Emit(bl        , vec2(0), 0, 0);        // 1
        Emit(bl + sizeV, vec2(0), 0, 0);        // 2
        Emit(tl        , vec2(0), 0, 0);        // 3

        sizeV.y *= -1;   // flip down
        Emit(tl + sizeV, vec2(0), 0, 0);        // 4
        Emit(tr        , vec2(0), 0, 0);        // 5

        sizeV.x *= -1;   // flip left
        Emit(tr + sizeV, vec2(0), 0, 0);        // 6
        Emit(br        , vec2(0), 0, 0);        // 7

        sizeV.y *= -1;   // flip back up
        Emit(br + sizeV, vec2(0), 0, 0);        // 8
        Emit(bl        , vec2(0), 0, 0);        // 9

        sizeV.x *= -1;   // flip back right (now == original sizeV)
        Emit(bl + sizeV, vec2(0), 0, 0);        // 10

    } else {    // everything else
        // uv-space border width, calculated in a very stupid way
        float borderWidth = distance(proj.matrix*bl, proj.matrix*(bl + vec4(inData[0].borderWidth,0,0,0)));
        borderWidth /= distance(proj.matrix*bl, proj.matrix*br);
        Emit(bl, vec2(0, 0), borderWidth, deform);
        Emit(br, vec2(1, 0), borderWidth, deform);
        Emit(tl, vec2(0, 1), borderWidth, deform);
        Emit(tr, vec2(1, 1), borderWidth, deform);
    }

    EndPrimitive();
}
