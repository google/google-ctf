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



#include "ILI9225.h"
#include "pin_configuration.h"
#include "spi.h"

#include <avr/interrupt.h>
#include <avr/pgmspace.h>
#include <util/delay.h>

template <typename T> void swap(T *a, T *b) {
    T t = *a;
    *a = *b;
    *b = t;
}

static void rotate_screen_coords(uint8_t *x, uint8_t *y) {
    *y = ILI9225_LCD_WIDTH - (*y + 1);
    swap(x, y);
}

namespace Display {

static void send_u16(uint16_t v) {
    PORTB &= ~PortB::CS_DSPL;
    SPI::transceive(v >> 8);
    SPI::transceive(v & 0xFF);
    PORTB |= PortB::CS_DSPL;
}

static void send_command(uint16_t cmd) {
    PORTB &= ~PortB::RS;
    send_u16(cmd);
}

static void send_data(uint16_t data) {
    PORTB |= PortB::RS;
    send_u16(data);
}

static void set_register(uint16_t reg, uint16_t val) {
    send_command(reg);
    send_data(val);
}

static void set_draw_window(uint8_t x0, uint8_t y0, uint8_t x1, uint8_t y1,
                            bool do_rotate) {
    // Make sure we rotate the screen.
    if (do_rotate) {
        rotate_screen_coords(&x0, &y0);
        rotate_screen_coords(&x1, &y1);

        if (x0 > x1) {
            swap(&x0, &x1);
        }

        if (y0 > y1) {
            swap(&y0, &y1);
        }
    }

    set_register(ILI9225_HORIZONTAL_WINDOW_ADDR1, x1);
    set_register(ILI9225_HORIZONTAL_WINDOW_ADDR2, x0);
    set_register(ILI9225_VERTICAL_WINDOW_ADDR1, y1);
    set_register(ILI9225_VERTICAL_WINDOW_ADDR2, y0);
    set_register(ILI9225_RAM_ADDR_SET1, x0);
    set_register(ILI9225_RAM_ADDR_SET2, y0);
    send_command(0x0022);
}

void init() {
    // RS, DSPL_RESET, CS_DSPL <- output
    DDRB |= PortB::RS | PortB::CS_DSPL | PortB::DSPL_RESET;

    // Reset display
    PORTB &= ~PortB::DSPL_RESET;
    _delay_ms(10);
    PORTB |= PortB::DSPL_RESET;
    _delay_ms(50);

    // Set power control registers [1]
    set_register(ILI9225_POWER_CTRL1, 0x0000);
    set_register(ILI9225_POWER_CTRL2, 0x0000);
    set_register(ILI9225_POWER_CTRL3, 0x0000);
    set_register(ILI9225_POWER_CTRL4, 0x0000);
    set_register(ILI9225_POWER_CTRL5, 0x0000);
    _delay_ms(40);

    // Set power control registers [2]
    set_register(ILI9225_POWER_CTRL2, 0x0018);
    set_register(ILI9225_POWER_CTRL3, 0x6121);
    set_register(ILI9225_POWER_CTRL4, 0x006F);
    set_register(ILI9225_POWER_CTRL5, 0x495F);
    set_register(ILI9225_POWER_CTRL1, 0x0800);
    _delay_ms(10);

    set_register(ILI9225_POWER_CTRL2, 0x103B);
    _delay_ms(50);

    // Initial display configuration
    set_register(ILI9225_DRIVER_OUTPUT_CTRL, 0x011C);
    set_register(ILI9225_LCD_AC_DRIVING_CTRL, 0x0100);
    set_register(ILI9225_ENTRY_MODE, 0x1030);
    set_register(ILI9225_DISP_CTRL1, 0x0000);
    set_register(ILI9225_BLANK_PERIOD_CTRL1, 0x0808);
    set_register(ILI9225_FRAME_CYCLE_CTRL, 0x1100);
    set_register(ILI9225_INTERFACE_CTRL, 0x0000);
    set_register(ILI9225_OSC_CTRL, 0x0701);
    set_register(ILI9225_VCI_RECYCLING, 0x0020);
    set_register(ILI9225_RAM_ADDR_SET1, 0x0000);
    set_register(ILI9225_RAM_ADDR_SET2, 0x0000);
    set_register(ILI9225_GATE_SCAN_CTRL, 0x0000);
    set_register(ILI9225_VERTICAL_SCROLL_CTRL1, 0x00DB);
    set_register(ILI9225_VERTICAL_SCROLL_CTRL2, 0x0000);
    set_register(ILI9225_VERTICAL_SCROLL_CTRL3, 0x0000);
    set_register(ILI9225_PARTIAL_DRIVING_POS1, 0x00DB);
    set_register(ILI9225_PARTIAL_DRIVING_POS2, 0x0000);
    set_register(ILI9225_HORIZONTAL_WINDOW_ADDR1, 0x00AF);
    set_register(ILI9225_HORIZONTAL_WINDOW_ADDR2, 0x0000);
    set_register(ILI9225_VERTICAL_WINDOW_ADDR1, 0x00DB);
    set_register(ILI9225_VERTICAL_WINDOW_ADDR2, 0x0000);
    set_register(ILI9225_GAMMA_CTRL1, 0x0000);
    set_register(ILI9225_GAMMA_CTRL2, 0x0808);
    set_register(ILI9225_GAMMA_CTRL3, 0x080A);
    set_register(ILI9225_GAMMA_CTRL4, 0x000A);
    set_register(ILI9225_GAMMA_CTRL5, 0x0A08);
    set_register(ILI9225_GAMMA_CTRL6, 0x0808);
    set_register(ILI9225_GAMMA_CTRL7, 0x0000);
    set_register(ILI9225_GAMMA_CTRL8, 0x0A00);
    set_register(ILI9225_GAMMA_CTRL9, 0x0710);
    set_register(ILI9225_GAMMA_CTRL10, 0x0710);

    // Enable display
    set_register(ILI9225_DISP_CTRL1, 0x0012);
    _delay_ms(50);
    set_register(ILI9225_DISP_CTRL1, 0x1017);
    clear();
}

void clear(uint16_t color) {
    cli();
    set_draw_window(0, 0, ILI9225_LCD_WIDTH, ILI9225_LCD_HEIGHT, false);
    for (uint16_t t = (ILI9225_LCD_WIDTH + 1) * (ILI9225_LCD_HEIGHT + 1); t > 0;
         t--) {
        send_data(color);
    }
    sei();
}

void draw_pixel(uint8_t x, uint8_t y, uint16_t color) {
    cli();
    set_draw_window(x, y, x + 1, y + 1, true);
    send_data(color);
    sei();
}

void fill_box(uint8_t x0, uint8_t y0, uint8_t x1, uint8_t y1, uint16_t color) {
    cli();
    set_draw_window(x0, y0, x1, y1, true);
    for (uint16_t t = (y1 - y0 + 1) * (x1 - x0 + 1); t > 0; t--) {
        send_data(color);
    }
    sei();
}

// Font converted from
// https://github.com/olikraus/u8glib/tree/master/tools/font/bdf 5x7.bdf
static const uint8_t font[][5] PROGMEM = {
    {0x00, 0x00, 0x00, 0x00, 0x00}, // ' '
    {0x00, 0x00, 0x2F, 0x00, 0x00}, // '!'
    {0x00, 0x07, 0x00, 0x07, 0x00}, // '"'
    {0x14, 0x3E, 0x14, 0x3E, 0x14}, // '#'
    {0x04, 0x2A, 0x3E, 0x2A, 0x10}, // '$'
    {0x13, 0x08, 0x04, 0x32, 0x00}, // '%'
    {0x14, 0x2A, 0x14, 0x20, 0x00}, // '&'
    {0x00, 0x00, 0x07, 0x00, 0x00}, // '''
    {0x00, 0x1E, 0x21, 0x00, 0x00}, // '('
    {0x00, 0x21, 0x1E, 0x00, 0x00}, // ')'
    {0x00, 0x2A, 0x1C, 0x2A, 0x00}, // '*'
    {0x08, 0x08, 0x3E, 0x08, 0x08}, // '+'
    {0x00, 0x40, 0x30, 0x10, 0x00}, // ','
    {0x08, 0x08, 0x08, 0x08, 0x00}, // '-'
    {0x00, 0x30, 0x30, 0x00, 0x00}, // '.'
    {0x10, 0x08, 0x04, 0x02, 0x00}, // '/'
    {0x00, 0x1E, 0x21, 0x1E, 0x00}, // '0'
    {0x00, 0x22, 0x3F, 0x20, 0x00}, // '1'
    {0x22, 0x31, 0x29, 0x26, 0x00}, // '2'
    {0x11, 0x25, 0x25, 0x1B, 0x00}, // '3'
    {0x0C, 0x0A, 0x3F, 0x08, 0x00}, // '4'
    {0x17, 0x25, 0x25, 0x19, 0x00}, // '5'
    {0x1E, 0x25, 0x25, 0x18, 0x00}, // '6'
    {0x01, 0x31, 0x0D, 0x03, 0x00}, // '7'
    {0x1A, 0x25, 0x25, 0x1A, 0x00}, // '8'
    {0x06, 0x29, 0x29, 0x1E, 0x00}, // '9'
    {0x00, 0x36, 0x36, 0x00, 0x00}, // ':'
    {0x40, 0x36, 0x16, 0x00, 0x00}, // ';'
    {0x00, 0x08, 0x14, 0x22, 0x00}, // '<'
    {0x14, 0x14, 0x14, 0x14, 0x00}, // '='
    {0x00, 0x22, 0x14, 0x08, 0x00}, // '>'
    {0x00, 0x02, 0x29, 0x06, 0x00}, // '?'
    {0x1E, 0x21, 0x2D, 0x0E, 0x00}, // '@'
    {0x3E, 0x09, 0x09, 0x3E, 0x00}, // 'A'
    {0x3F, 0x25, 0x25, 0x1A, 0x00}, // 'B'
    {0x1E, 0x21, 0x21, 0x12, 0x00}, // 'C'
    {0x3F, 0x21, 0x21, 0x1E, 0x00}, // 'D'
    {0x3F, 0x25, 0x25, 0x21, 0x00}, // 'E'
    {0x3F, 0x05, 0x05, 0x01, 0x00}, // 'F'
    {0x1E, 0x21, 0x29, 0x3A, 0x00}, // 'G'
    {0x3F, 0x04, 0x04, 0x3F, 0x00}, // 'H'
    {0x00, 0x21, 0x3F, 0x21, 0x00}, // 'I'
    {0x10, 0x20, 0x20, 0x1F, 0x00}, // 'J'
    {0x3F, 0x0C, 0x12, 0x21, 0x00}, // 'K'
    {0x3F, 0x20, 0x20, 0x20, 0x00}, // 'L'
    {0x3F, 0x06, 0x06, 0x3F, 0x00}, // 'M'
    {0x3F, 0x06, 0x18, 0x3F, 0x00}, // 'N'
    {0x1E, 0x21, 0x21, 0x1E, 0x00}, // 'O'
    {0x3F, 0x09, 0x09, 0x06, 0x00}, // 'P'
    {0x1E, 0x31, 0x21, 0x5E, 0x00}, // 'Q'
    {0x3F, 0x09, 0x19, 0x26, 0x00}, // 'R'
    {0x12, 0x25, 0x29, 0x12, 0x00}, // 'S'
    {0x00, 0x01, 0x3F, 0x01, 0x00}, // 'T'
    {0x1F, 0x20, 0x20, 0x1F, 0x00}, // 'U'
    {0x0F, 0x30, 0x30, 0x0F, 0x00}, // 'V'
    {0x3F, 0x18, 0x18, 0x3F, 0x00}, // 'W'
    {0x33, 0x0C, 0x0C, 0x33, 0x00}, // 'X'
    {0x00, 0x07, 0x38, 0x07, 0x00}, // 'Y'
    {0x31, 0x29, 0x25, 0x23, 0x00}, // 'Z'
    {0x00, 0x3F, 0x21, 0x21, 0x00}, // '['
    {0x02, 0x04, 0x08, 0x10, 0x00}, // '\'
    {0x00, 0x21, 0x21, 0x3F, 0x00}, // ']'
    {0x00, 0x02, 0x01, 0x02, 0x00}, // '^'
    {0x20, 0x20, 0x20, 0x20, 0x00}, // '_'
    {0x00, 0x01, 0x02, 0x00, 0x00}, // '`'
#ifdef FONT_LOWERCASE
    {0x18, 0x24, 0x14, 0x3C, 0x00}, // 'a'
    {0x3F, 0x24, 0x24, 0x18, 0x00}, // 'b'
    {0x18, 0x24, 0x24, 0x00, 0x00}, // 'c'
    {0x18, 0x24, 0x24, 0x3F, 0x00}, // 'd'
    {0x18, 0x34, 0x2C, 0x08, 0x00}, // 'e'
    {0x08, 0x3E, 0x09, 0x02, 0x00}, // 'f'
    {0x28, 0x54, 0x54, 0x4C, 0x00}, // 'g'
    {0x3F, 0x04, 0x04, 0x38, 0x00}, // 'h'
    {0x00, 0x24, 0x3D, 0x20, 0x00}, // 'i'
    {0x00, 0x20, 0x40, 0x3D, 0x00}, // 'j'
    {0x3F, 0x08, 0x14, 0x20, 0x00}, // 'k'
    {0x00, 0x21, 0x3F, 0x20, 0x00}, // 'l'
    {0x3C, 0x08, 0x0C, 0x38, 0x00}, // 'm'
    {0x3C, 0x04, 0x04, 0x38, 0x00}, // 'n'
    {0x18, 0x24, 0x24, 0x18, 0x00}, // 'o'
    {0x7C, 0x24, 0x24, 0x18, 0x00}, // 'p'
    {0x18, 0x24, 0x24, 0x7C, 0x00}, // 'q'
    {0x3C, 0x04, 0x04, 0x08, 0x00}, // 'r'
    {0x28, 0x2C, 0x34, 0x14, 0x00}, // 's'
    {0x04, 0x1F, 0x24, 0x20, 0x00}, // 't'
    {0x1C, 0x20, 0x20, 0x3C, 0x00}, // 'u'
    {0x00, 0x1C, 0x20, 0x1C, 0x00}, // 'v'
    {0x3C, 0x30, 0x30, 0x3C, 0x00}, // 'w'
    {0x24, 0x18, 0x18, 0x24, 0x00}, // 'x'
    {0x0C, 0x50, 0x20, 0x1C, 0x00}, // 'y'
    {0x24, 0x34, 0x2C, 0x24, 0x00}, // 'z'
#endif                              // FONT_LOWERCASE
    {0x00, 0x04, 0x1E, 0x21, 0x00}, // '{'
    {0x00, 0x00, 0x3F, 0x00, 0x00}, // '|'
    {0x00, 0x21, 0x1E, 0x04, 0x00}, // '}'
    {0x02, 0x01, 0x02, 0x01, 0x00}, // '~'
};

void draw_char(unsigned char c, uint8_t x, uint8_t y, uint16_t color,
               uint16_t bgcolor) {
    if (c < 0x20 || c > 0x7F)
        return;
#ifndef FONT_LOWERCASE
    if (c >= 'a') {
        c = c - 'a' + 'A';
    }
#endif
    c -= 0x20;
    for (uint8_t line = 0; line < 5; line++) {
        for (uint8_t col = 0; col < 8; col++) {
            bool mark = pgm_read_byte(&font[c][line]) & (1 << col);
            if (mark) {
                draw_pixel(x + line, y + col, color);
            } else {
                draw_pixel(x + line, y + col, bgcolor);
            }
        }
    }
}

void draw_number(uint8_t num, uint8_t x, uint8_t y, uint16_t color,
                 uint16_t bgcolor) {
    if (num > 9) {
        return;
    }
    draw_char(num + '0', x, y, color, bgcolor);
}

void draw_numbers(uint16_t num, uint8_t n_digits, uint8_t x, uint8_t y,
                  uint16_t color, uint16_t bgcolor) {
    fill_box(x, y, x + n_digits * char_width, y + char_height, bgcolor);
    for (uint8_t i = 0; i < n_digits; i++) {
        draw_number(num % 10, x + (n_digits - i - 1) * (char_width + 1), y,
                    color, bgcolor);
        num /= 10;
    }
}

void draw_text(const char *msg, uint8_t x, uint8_t y, uint16_t color,
               uint16_t bgcolor) {
    // This is not a typo.
    // We rotate the screen by 90deg, therefore w => h
    while (*msg && x < ILI9225_LCD_HEIGHT) {
        draw_char(*msg++, x, y, color, bgcolor);
        x += char_width + 1;
    }
}

void draw_text_pgm(const char *msg, uint8_t x, uint8_t y, uint16_t color,
                   uint16_t bgcolor) {
    // This is not a typo.
    // We rotate the screen by 90deg, therefore w => h
    char c;
    while ((c = pgm_read_byte(msg++)) && x < ILI9225_LCD_HEIGHT) {
        draw_char(c, x, y, color, bgcolor);
        x += char_width + 1;
    }
}

void draw_box(uint8_t x0, uint8_t y0, uint8_t x1, uint8_t y1, uint16_t color) {
    draw_line(x0, y0, x1, y0, color);
    draw_line(x0, y0, x0, y1, color);
    draw_line(x1, y0, x1, y1, color);
    draw_line(x0, y1, x1, y1, color);
}

void draw_line(uint8_t x0, uint8_t y0, uint8_t x1, uint8_t y1, uint16_t color) {
    // May only be used to draw straight lines (reduce required space)
    cli();
    uint8_t w = 0;
    if (x0 == x1) {
        w = y1 - y0;
    } else if (y0 == y1) {
        w = x1 - x0;
    }
    if (w) {
        set_draw_window(x0, y0, x1, y1, true);
        for (uint8_t i = 0; i < w; i++) {
            send_data(color);
        }
    }
    sei();
}

} // namespace Display
