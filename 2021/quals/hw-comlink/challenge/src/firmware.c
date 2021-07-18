// Copyright 2021 Google LLC
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

#include <stdint.h>
#include <string.h>

#define IO_CTRL_TX 0
#define IO_CTRL_RX 1

#define RAM_BASE 0x8000

#define AES_OUT_OFFSET 0x10
#define AES_IN_OFFSET 0x20

#define AES_OUT_ADDR (uint8_t*)(RAM_BASE+AES_OUT_OFFSET)
#define AES_IN_ADDR (uint8_t*)(RAM_BASE+AES_IN_OFFSET)

__sfr __at 0x00 IoData;
__sfr __at 0x01 IoCtrl;
__sfr __at AES_OUT_OFFSET AesOut;
__sfr __at AES_IN_OFFSET AesIn;
__sfr __at 0x30 AesCtrl;

char HEX[16] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};


void putc(unsigned char c) {
    while((IoCtrl>>IO_CTRL_TX) & 1);
    IoData = c;
    IoCtrl |= (1<<IO_CTRL_TX);
}

void puts(char *s) {
    do {
        putc(*s);
    } while (*s++);
}

void write(unsigned char* src, unsigned short len) {
    while(len--) {
        putc(*src++);
    }
}

void puthex(unsigned char c) {
    putc(HEX[(c >> 4) & 0xF]);
    putc(HEX[(c >> 0) & 0xF]);
}

unsigned char getc() {
    IoCtrl |= (1<<IO_CTRL_RX);
    while((IoCtrl>>IO_CTRL_RX) & 1);
    return IoData;
}

void aes_encrypt(uint8_t *block) {
    memcpy(AES_OUT_ADDR, block, 16);
    AesCtrl |= 1;
    while(AesCtrl & 1);
    memcpy(block, AES_IN_ADDR, 16);
}

#ifdef DEBUG
void basic_tests1(void) {
    unsigned char a;
    unsigned char b = 0;

    for ( a = 0; a < 10; a++ )
    {
        b += a;
    }

    *(unsigned char*)(0x8100) = b;

    putc('H');
    puts("ello ");
    write("World!\n", 7);

    for ( a = 0; a < 5; a++ ) {
        putc(getc());
    }
}

void aes_tests1(void) {
    puts("BLOCK: ");
    uint8_t block[16];
    memset(block, 0, 16);
    for (size_t a = 0; a < 16; a++ ) {
        puthex(block[a]);
    }
    putc('\n');

    aes_encrypt(block);

    // Expected result: 66e94bd4ef8a2c3b884cfa59ca342b2e
    puts("BLOCK: ");
    for (size_t a = 0; a < 16; a++ ) {
        puthex(block[a]);
    }
    putc('\n');
}

uint8_t aes_encrypt_leak(uint8_t *block, uint8_t idx) {
    memcpy(AES_OUT_ADDR, block, 16);
    AesCtrl |= 1;
    __asm
    nop
    __endasm;
    //AesCtrl |= 1;
    AesCtrl = 1; //Save a few cycles
    return (AES_IN_ADDR)[idx];
}

void exploit(void) {
    for (uint8_t val = 0; val < 0x10; val++)
    {
        puts("VAL: ");
        puthex(val*0x10);
        puts(" LEAK: ");
        uint8_t block[16];
        for (size_t i = 0; i < 16; i++)
        {
            memset(block, val*0x10, 16);
            uint8_t c = aes_encrypt_leak(block, i);
            puthex(c);
        }
        putc('\n');
    }
}
#endif

int main()
{
    #ifdef DEBUG
    //basic_tests1();
    //aes_tests1();

    exploit();
    #else

    uint8_t block1[16];
    uint8_t block2[16];
    uint8_t *block_prev = block1;
    uint8_t *block_cur = block2;
    uint8_t last = 0;
    uint8_t pad = 0;
    memset(block1, 'X', 16);
    while(1) {
        size_t num_input = 0;
        for(num_input = 0; num_input < 16; num_input++) {
            block_cur[num_input] = getc();
            if(block_cur[num_input] == '\n') {
                last = 1;
                break;
            }
        }

        if(last == 1) {
            pad = 16 - (num_input % 16);
            for(; num_input < 16; num_input++) {
                block_cur[num_input] = pad;
            }
        }

        for(size_t i = 0; i < 16; i++) {
            block_cur[i] ^= block_prev[i];
        }
        aes_encrypt(block_cur);
        for(size_t i = 0; i < 16; i++) {
            putc(block_cur[i]);
        }

        uint8_t* tmp = block_prev;
        block_prev = block_cur;
        block_cur = tmp;

        if(last == 1) {
            break;
        }
    }

    // Even blocks, add pad block
    if(pad == 0) {
        for(size_t i = 0; i < 16; i++) {
            block_cur[i] = block_prev[i] ^ 0x10;
        }
        aes_encrypt(block_cur);
        for(size_t i = 0; i < 16; i++) {
            putc(block_cur[i]);
        }
    }

    #endif

    return 0;
}
