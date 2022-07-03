#version 460

// Copyright 2022 Google LLC
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

// Author: Carl Svensson

//TODO: remove all function and variable names

const int BLOCK_SIZE = 1024;
const int SUB_MATRIX_SIZE = 4*4;
const int MATRIX_SIZE = 4*4*SUB_MATRIX_SIZE;
const int BLOCK_NUM_SUB_MATRICES = BLOCK_SIZE / SUB_MATRIX_SIZE;
const int BLOCK_NUM_MATRICES = BLOCK_SIZE / MATRIX_SIZE ;

layout (location = 0) out vec4 FragColor;

layout (location = 0) uniform uvec2 u_resolution;
layout (location = 1) uniform uint u_block_count;
layout (location = 2) uniform mat4 u_nonce[16];

layout(std430, binding = 0) buffer input_data
{
    mat4 data[];
};

const mat4 diffusion[16] = mat4[](
    mat4(97.0, 15.0, 52.0, 185.0, 99.0, 64.0, 43.0, 201.0, 230.0, 107.0, 122.0, 236.0, 168.0, 189.0, 150.0, 145.0),
    mat4(121.0, 45.0, 186.0, 66.0, 240.0, 74.0, 206.0, 29.0, 47.0, 250.0, 37.0, 174.0, 200.0, 253.0, 0.0, 53.0),
    mat4(161.0, 19.0, 128.0, 228.0, 90.0, 170.0, 155.0, 169.0, 131.0, 8.0, 122.0, 40.0, 166.0, 187.0, 62.0, 167.0),
    mat4(230.0, 32.0, 19.0, 18.0, 241.0, 213.0, 243.0, 81.0, 25.0, 62.0, 171.0, 232.0, 229.0, 152.0, 163.0, 71.0),
    mat4(66.0, 249.0, 233.0, 93.0, 230.0, 166.0, 237.0, 203.0, 63.0, 197.0, 230.0, 103.0, 241.0, 197.0, 238.0, 85.0),
    mat4(38.0, 103.0, 159.0, 162.0, 48.0, 157.0, 174.0, 218.0, 99.0, 64.0, 119.0, 170.0, 15.0, 65.0, 30.0, 75.0),
    mat4(9.0, 141.0, 21.0, 74.0, 87.0, 223.0, 0.0, 176.0, 218.0, 248.0, 1.0, 89.0, 129.0, 4.0, 169.0, 6.0),
    mat4(155.0, 143.0, 94.0, 179.0, 49.0, 102.0, 195.0, 35.0, 127.0, 140.0, 55.0, 230.0, 38.0, 83.0, 199.0, 159.0),
    mat4(32.0, 79.0, 97.0, 239.0, 220.0, 107.0, 170.0, 220.0, 26.0, 46.0, 84.0, 148.0, 42.0, 107.0, 117.0, 50.0),
    mat4(174.0, 213.0, 71.0, 205.0, 150.0, 19.0, 248.0, 198.0, 139.0, 249.0, 64.0, 220.0, 21.0, 96.0, 117.0, 218.0),
    mat4(150.0, 237.0, 154.0, 21.0, 129.0, 60.0, 63.0, 208.0, 159.0, 253.0, 153.0, 133.0, 80.0, 110.0, 246.0, 174.0),
    mat4(250.0, 138.0, 193.0, 41.0, 190.0, 15.0, 103.0, 64.0, 185.0, 18.0, 4.0, 96.0, 91.0, 208.0, 54.0, 176.0),
    mat4(219.0, 240.0, 70.0, 191.0, 149.0, 203.0, 33.0, 255.0, 251.0, 104.0, 34.0, 204.0, 120.0, 165.0, 248.0, 54.0),
    mat4(143.0, 0.0, 218.0, 117.0, 212.0, 146.0, 38.0, 102.0, 45.0, 51.0, 194.0, 158.0, 108.0, 25.0, 61.0, 149.0),
    mat4(157.0, 83.0, 170.0, 85.0, 128.0, 18.0, 117.0, 154.0, 77.0, 41.0, 178.0, 85.0, 54.0, 96.0, 15.0, 118.0),
    mat4(191.0, 254.0, 38.0, 124.0, 239.0, 246.0, 1.0, 16.0, 51.0, 82.0, 53.0, 246.0, 2.0, 181.0, 181.0, 196.0)
);

const mat4 k0[16] = mat4[](
    mat4(102.0, 148.0, 54.0, 11.0, 113.0, 233.0, 219.0, 96.0, 196.0, 70.0, 128.0, 97.0, 7.0, 143.0, 123.0, 211.0),
    mat4(244.0, 136.0, 121.0, 170.0, 112.0, 186.0, 107.0, 182.0, 241.0, 255.0, 97.0, 18.0, 233.0, 243.0, 247.0, 13.0),
    mat4(88.0, 127.0, 108.0, 173.0, 31.0, 8.0, 220.0, 183.0, 2.0, 167.0, 119.0, 47.0, 14.0, 135.0, 210.0, 34.0),
    mat4(0.0, 162.0, 51.0, 235.0, 36.0, 59.0, 108.0, 40.0, 198.0, 130.0, 199.0, 106.0, 127.0, 23.0, 35.0, 63.0),
    mat4(214.0, 22.0, 220.0, 102.0, 195.0, 88.0, 98.0, 195.0, 54.0, 194.0, 105.0, 161.0, 211.0, 111.0, 122.0, 191.0),
    mat4(116.0, 29.0, 140.0, 27.0, 120.0, 3.0, 90.0, 76.0, 111.0, 86.0, 110.0, 83.0, 129.0, 78.0, 71.0, 206.0),
    mat4(204.0, 57.0, 106.0, 196.0, 180.0, 96.0, 139.0, 10.0, 127.0, 52.0, 56.0, 91.0, 130.0, 149.0, 200.0, 38.0),
    mat4(57.0, 138.0, 146.0, 127.0, 254.0, 242.0, 98.0, 235.0, 96.0, 115.0, 223.0, 233.0, 214.0, 115.0, 8.0, 194.0),
    mat4(218.0, 11.0, 116.0, 135.0, 150.0, 40.0, 241.0, 236.0, 76.0, 128.0, 42.0, 87.0, 9.0, 62.0, 32.0, 133.0),
    mat4(115.0, 73.0, 201.0, 105.0, 138.0, 22.0, 234.0, 169.0, 165.0, 221.0, 138.0, 225.0, 112.0, 157.0, 200.0, 38.0),
    mat4(249.0, 80.0, 72.0, 162.0, 84.0, 145.0, 190.0, 189.0, 221.0, 143.0, 26.0, 114.0, 18.0, 69.0, 211.0, 230.0),
    mat4(245.0, 158.0, 15.0, 44.0, 168.0, 14.0, 248.0, 50.0, 254.0, 8.0, 12.0, 192.0, 24.0, 191.0, 174.0, 32.0),
    mat4(243.0, 166.0, 79.0, 32.0, 198.0, 115.0, 254.0, 55.0, 4.0, 160.0, 137.0, 201.0, 13.0, 124.0, 57.0, 238.0),
    mat4(250.0, 75.0, 137.0, 218.0, 27.0, 84.0, 10.0, 136.0, 194.0, 102.0, 33.0, 98.0, 236.0, 132.0, 28.0, 2.0),
    mat4(219.0, 219.0, 48.0, 232.0, 73.0, 211.0, 252.0, 225.0, 239.0, 229.0, 164.0, 246.0, 179.0, 147.0, 139.0, 176.0),
    mat4(44.0, 155.0, 91.0, 224.0, 10.0, 182.0, 78.0, 87.0, 22.0, 255.0, 202.0, 149.0, 84.0, 15.0, 47.0, 16.0)
);

const mat4 k1[16] = mat4[](
    mat4(102.0, 85.0, 19.0, 195.0, 140.0, 247.0, 54.0, 25.0, 9.0, 246.0, 179.0, 52.0, 159.0, 186.0, 204.0, 57.0),
    mat4(146.0, 201.0, 231.0, 2.0, 171.0, 161.0, 63.0, 78.0, 34.0, 209.0, 147.0, 121.0, 115.0, 206.0, 254.0, 112.0),
    mat4(44.0, 220.0, 249.0, 115.0, 3.0, 57.0, 250.0, 38.0, 165.0, 214.0, 62.0, 183.0, 41.0, 223.0, 41.0, 194.0),
    mat4(149.0, 3.0, 230.0, 174.0, 212.0, 115.0, 47.0, 244.0, 189.0, 34.0, 50.0, 101.0, 106.0, 169.0, 2.0, 130.0),
    mat4(203.0, 40.0, 210.0, 103.0, 32.0, 174.0, 27.0, 100.0, 231.0, 168.0, 203.0, 105.0, 58.0, 129.0, 52.0, 110.0),
    mat4(231.0, 167.0, 103.0, 212.0, 158.0, 125.0, 166.0, 164.0, 156.0, 216.0, 72.0, 241.0, 217.0, 234.0, 142.0, 62.0),
    mat4(49.0, 78.0, 76.0, 16.0, 33.0, 143.0, 91.0, 176.0, 90.0, 78.0, 150.0, 111.0, 94.0, 129.0, 233.0, 221.0),
    mat4(14.0, 212.0, 128.0, 18.0, 65.0, 246.0, 105.0, 41.0, 176.0, 227.0, 96.0, 190.0, 61.0, 204.0, 173.0, 201.0),
    mat4(17.0, 237.0, 24.0, 111.0, 110.0, 169.0, 96.0, 146.0, 143.0, 212.0, 199.0, 40.0, 237.0, 124.0, 221.0, 36.0),
    mat4(125.0, 199.0, 26.0, 199.0, 200.0, 11.0, 76.0, 39.0, 159.0, 159.0, 109.0, 160.0, 26.0, 201.0, 55.0, 26.0),
    mat4(76.0, 204.0, 245.0, 147.0, 66.0, 213.0, 171.0, 245.0, 10.0, 17.0, 230.0, 49.0, 1.0, 23.0, 224.0, 151.0),
    mat4(144.0, 161.0, 7.0, 84.0, 11.0, 27.0, 13.0, 32.0, 136.0, 71.0, 28.0, 154.0, 254.0, 167.0, 75.0, 12.0),
    mat4(123.0, 248.0, 247.0, 60.0, 201.0, 90.0, 195.0, 245.0, 191.0, 43.0, 225.0, 14.0, 240.0, 137.0, 147.0, 192.0),
    mat4(65.0, 103.0, 198.0, 54.0, 218.0, 174.0, 170.0, 134.0, 71.0, 5.0, 113.0, 222.0, 185.0, 239.0, 213.0, 201.0),
    mat4(214.0, 54.0, 42.0, 187.0, 3.0, 68.0, 16.0, 146.0, 182.0, 58.0, 32.0, 101.0, 80.0, 50.0, 60.0, 57.0),
    mat4(1.0, 146.0, 133.0, 202.0, 2.0, 243.0, 93.0, 45.0, 27.0, 75.0, 4.0, 75.0, 128.0, 175.0, 63.0, 247.0)
);

const mat4 k2[16] = mat4[](
    mat4(212.0, 51.0, 251.0, 31.0, 136.0, 37.0, 62.0, 3.0, 54.0, 242.0, 184.0, 241.0, 35.0, 228.0, 61.0, 203.0),
    mat4(164.0, 217.0, 127.0, 198.0, 44.0, 235.0, 143.0, 129.0, 202.0, 154.0, 239.0, 95.0, 26.0, 242.0, 110.0, 175.0),
    mat4(87.0, 220.0, 116.0, 20.0, 50.0, 40.0, 147.0, 16.0, 22.0, 2.0, 99.0, 232.0, 190.0, 147.0, 185.0, 61.0),
    mat4(80.0, 99.0, 165.0, 180.0, 248.0, 130.0, 48.0, 48.0, 43.0, 116.0, 182.0, 73.0, 96.0, 211.0, 61.0, 117.0),
    mat4(106.0, 160.0, 232.0, 156.0, 177.0, 234.0, 3.0, 191.0, 73.0, 113.0, 72.0, 34.0, 154.0, 60.0, 94.0, 168.0),
    mat4(246.0, 83.0, 169.0, 21.0, 180.0, 197.0, 92.0, 249.0, 203.0, 39.0, 154.0, 91.0, 131.0, 70.0, 109.0, 234.0),
    mat4(56.0, 245.0, 82.0, 175.0, 133.0, 53.0, 141.0, 91.0, 9.0, 123.0, 29.0, 145.0, 105.0, 248.0, 183.0, 22.0),
    mat4(178.0, 206.0, 43.0, 128.0, 45.0, 189.0, 36.0, 18.0, 112.0, 175.0, 125.0, 252.0, 213.0, 62.0, 113.0, 237.0),
    mat4(49.0, 0.0, 254.0, 128.0, 120.0, 152.0, 100.0, 73.0, 65.0, 23.0, 255.0, 44.0, 68.0, 115.0, 9.0, 219.0),
    mat4(99.0, 250.0, 175.0, 18.0, 30.0, 161.0, 7.0, 179.0, 225.0, 142.0, 98.0, 92.0, 200.0, 94.0, 212.0, 220.0),
    mat4(96.0, 156.0, 68.0, 49.0, 215.0, 136.0, 67.0, 45.0, 215.0, 186.0, 152.0, 47.0, 140.0, 73.0, 176.0, 179.0),
    mat4(239.0, 206.0, 117.0, 93.0, 177.0, 39.0, 194.0, 78.0, 66.0, 221.0, 150.0, 147.0, 78.0, 76.0, 25.0, 139.0),
    mat4(43.0, 90.0, 117.0, 187.0, 117.0, 108.0, 232.0, 204.0, 101.0, 62.0, 25.0, 214.0, 50.0, 83.0, 43.0, 151.0),
    mat4(172.0, 96.0, 136.0, 109.0, 167.0, 8.0, 33.0, 79.0, 103.0, 251.0, 180.0, 214.0, 33.0, 116.0, 141.0, 11.0),
    mat4(117.0, 123.0, 161.0, 60.0, 79.0, 104.0, 82.0, 76.0, 149.0, 32.0, 56.0, 160.0, 173.0, 112.0, 174.0, 184.0),
    mat4(36.0, 81.0, 20.0, 81.0, 165.0, 159.0, 126.0, 171.0, 52.0, 14.0, 5.0, 126.0, 176.0, 175.0, 99.0, 88.0)
);


void mul_mat16(out mat4 res[16], in mat4 a[16], in mat4 b[16]) {
    res[0] = a[0]*b[0] + a[1]*b[4] + a[2]*b[8] + a[3]*b[12];
    res[1] = a[0]*b[1] + a[1]*b[5] + a[2]*b[9] + a[3]*b[13];
    res[2] = a[0]*b[2] + a[1]*b[6] + a[2]*b[10] + a[3]*b[14];
    res[3] = a[0]*b[3] + a[1]*b[7] + a[2]*b[11] + a[3]*b[15];
    res[4] = a[4]*b[0] + a[5]*b[4] + a[6]*b[8] + a[7]*b[12];
    res[5] = a[4]*b[1] + a[5]*b[5] + a[6]*b[9] + a[7]*b[13];
    res[6] = a[4]*b[2] + a[5]*b[6] + a[6]*b[10] + a[7]*b[14];
    res[7] = a[4]*b[3] + a[5]*b[7] + a[6]*b[11] + a[7]*b[15];
    res[8] = a[10]*b[8] + a[11]*b[12] + a[8]*b[0] + a[9]*b[4];
    res[9] = a[10]*b[9] + a[11]*b[13] + a[8]*b[1] + a[9]*b[5];
    res[10] = a[10]*b[10] + a[11]*b[14] + a[8]*b[2] + a[9]*b[6];
    res[11] = a[10]*b[11] + a[11]*b[15] + a[8]*b[3] + a[9]*b[7];
    res[12] = a[12]*b[0] + a[13]*b[4] + a[14]*b[8] + a[15]*b[12];
    res[13] = a[12]*b[1] + a[13]*b[5] + a[14]*b[9] + a[15]*b[13];
    res[14] = a[12]*b[2] + a[13]*b[6] + a[14]*b[10] + a[15]*b[14];
    res[15] = a[12]*b[3] + a[13]*b[7] + a[14]*b[11] + a[15]*b[15];
}

void set_mat16(inout mat4 data[16], in int val) {
   for(int i = 0; i < 16; i++) {
     for(int col = 0; col < 4; col++) {
       for(int row = 0; row < 4; row++) {
         data[i][col][row] = float(val);
       }
     }
   }
}

void mod_mat16(inout mat4 data[16]) {
   for(int i = 0; i < 16; i++) {
     for(int col = 0; col < 4; col++) {
       for(int row = 0; row < 4; row++) {
         data[i][col][row] = mod(data[i][col][row], 256.0);
       }
     }
   }
}

void copy_mat16(out mat4 dst[16], in mat4 src[16]) {
    for(int i = 0; i < 16; i++) {
        dst[i] = src[i];
    }
}

void add_mat16(inout mat4 dst[16], in mat4 src[16]) {
    for(int i = 0; i < 16; i++) {
        dst[i] += src[i];
    }
}

void add_mat16(out mat4 res[16], in mat4 a[16], in mat4 b[16]) {
    for(int i = 0; i < 16; i++) {
        res[i] = a[i] + b[i];
    }
}

void sub_mat16(inout mat4 dst[16], in mat4 src[16]) {
    for(int i = 0; i < 16; i++) {
        dst[i] -= src[i];
    }
}

void f0(out mat4 dst[16], in mat4 m[16], in mat4 k[16]) {
    mat4 tmp[16];
    for(int i = 0; i < 16; i++) {
        for(int col = 0; col < 4; col++) {
            for(int row = 0; row < 4; row++) {
                tmp[i][col][row] = float(int(126.0 * (1.0+sin(m[i][col][row]))));
            }
        }
    }
    mod_mat16(tmp);
    mul_mat16(dst, tmp, k);
}

void f1(out mat4 dst[16], in mat4 m[16], in mat4 k[16]) {
    mat4 tmp[16];
    for(int i = 0; i < 16; i++) {
        for(int col = 0; col < 4; col++) {
            for(int row = 0; row < 4; row++) {
                tmp[i][col][row] = float(int(126.0 * (1.0+cos(m[i][col][row]))));
            }
        }
    }
    mod_mat16(tmp);
    mul_mat16(dst, tmp, k);
}

void f2(out mat4 dst[16], in mat4 m[16], in mat4 k[16]) {
    mat4 tmp[16];
    for(int i = 0; i < 16; i++) {
        for(int col = 0; col < 4; col++) {
            for(int row = 0; row < 4; row++) {
                tmp[i][col][row] = float(int(126.0 * (1.0+tan((m[i][col][row]-127.0)/256.0))));
            }
        }
    }
    mod_mat16(tmp);
    mul_mat16(dst, tmp, k);
}

void main()
{
    const uint pixel_index = (u_resolution.x * int(gl_FragCoord.y) + int(gl_FragCoord.x))*4;
    const uint pixel_row = (pixel_index / 4) % 4;
    const uint block_index = pixel_index / BLOCK_SIZE;
    const uint matrix_index = (pixel_index % BLOCK_SIZE) / MATRIX_SIZE;
    const uint element_index = pixel_index % MATRIX_SIZE;
    const uint submatrix_index = element_index / SUB_MATRIX_SIZE;

    const uint data_offset = (block_index * BLOCK_SIZE)/SUB_MATRIX_SIZE;

    if(block_index >= u_block_count) {
        FragColor = vec4(float(0xCC)/255.0, float(0xCC)/255.0, float(0xCC)/255.0, float(0xCC)/255.0);
        return;
    }

    mat4 nonce[16];
    copy_mat16(nonce, u_nonce);
    nonce[15][0][0] = float(2*(block_index+1)-1);

    mat4 M0[16];
    uint matrix_offset;
    uint matrix0_offset;

    mat4 res[16];

    // Create modifier block and get input offset
    if(matrix_index == 0) {
        matrix_offset = 1 * MATRIX_SIZE/SUB_MATRIX_SIZE;
        matrix0_offset = 0 * MATRIX_SIZE/SUB_MATRIX_SIZE;
    } else if(matrix_index == 1) {
        matrix_offset = 2 * MATRIX_SIZE/SUB_MATRIX_SIZE;
        matrix0_offset = 1 * MATRIX_SIZE/SUB_MATRIX_SIZE;
    } else if(matrix_index == 2) {
        matrix_offset = 3 * MATRIX_SIZE/SUB_MATRIX_SIZE;
        matrix0_offset = 2 * MATRIX_SIZE/SUB_MATRIX_SIZE;
    } else if(matrix_index == 3) {
        matrix_offset = 0 * MATRIX_SIZE/SUB_MATRIX_SIZE;
        matrix0_offset = -1;
    }

    // Init M0
    if(matrix_index >= 0 && matrix_index <= 2) {
        M0[0] = data[data_offset + matrix0_offset + 0];
        M0[1] = data[data_offset + matrix0_offset + 1];
        M0[2] = data[data_offset + matrix0_offset + 2];
        M0[3] = data[data_offset + matrix0_offset + 3];
        M0[4] = data[data_offset + matrix0_offset + 4];
        M0[5] = data[data_offset + matrix0_offset + 5];
        M0[6] = data[data_offset + matrix0_offset + 6];
        M0[7] = data[data_offset + matrix0_offset + 7];
        M0[8] = data[data_offset + matrix0_offset + 8];
        M0[9] = data[data_offset + matrix0_offset + 9];
        M0[10] = data[data_offset + matrix0_offset + 10];
        M0[11] = data[data_offset + matrix0_offset + 11];
        M0[12] = data[data_offset + matrix0_offset + 12];
        M0[13] = data[data_offset + matrix0_offset + 13];
        M0[14] = data[data_offset + matrix0_offset + 14];
        M0[15] = data[data_offset + matrix0_offset + 15];
    } else { // matrix_index == 3
        set_mat16(M0, 0);
    }

    if(matrix_index == 0) {
        f0(M0, M0, k0);
    } else if(matrix_index == 1) {
        f1(M0, M0, k1);
    } else if(matrix_index == 2) {
        f2(M0, M0, k2);
    }

    // Fetch input block
    res[0] = data[data_offset + matrix_offset + 0];
    res[1] = data[data_offset + matrix_offset + 1];
    res[2] = data[data_offset + matrix_offset + 2];
    res[3] = data[data_offset + matrix_offset + 3];
    res[4] = data[data_offset + matrix_offset + 4];
    res[5] = data[data_offset + matrix_offset + 5];
    res[6] = data[data_offset + matrix_offset + 6];
    res[7] = data[data_offset + matrix_offset + 7];
    res[8] = data[data_offset + matrix_offset + 8];
    res[9] = data[data_offset + matrix_offset + 9];
    res[10] = data[data_offset + matrix_offset + 10];
    res[11] = data[data_offset + matrix_offset + 11];
    res[12] = data[data_offset + matrix_offset + 12];
    res[13] = data[data_offset + matrix_offset + 13];
    res[14] = data[data_offset + matrix_offset + 14];
    res[15] = data[data_offset + matrix_offset + 15];

    // apply F-function
    mod_mat16(M0);
    add_mat16(res, M0);
    mod_mat16(res);

    // Apply nonce and diffusion
    mul_mat16(res, res, nonce);
    mod_mat16(res);
    mul_mat16(res, res, diffusion);
    mod_mat16(res);

    // Convert to "bytes"
    FragColor = vec4(
        float(res[submatrix_index][0][pixel_row])/255.0,
        float(res[submatrix_index][1][pixel_row])/255.0,
        float(res[submatrix_index][2][pixel_row])/255.0,
        float(res[submatrix_index][3][pixel_row])/255.0
    );
}
