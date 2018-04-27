/*
 * Copyright 2018 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */



#pragma once

#include <avr/io.h>
#include <avr/pgmspace.h>
#include <stdint.h>

// See ILI9225 datasheet
constexpr uint16_t ILI9225_LCD_WIDTH = 176;
constexpr uint16_t ILI9225_LCD_HEIGHT = 220;
constexpr uint8_t ILI9225_DRIVER_OUTPUT_CTRL = 0x01;
constexpr uint8_t ILI9225_LCD_AC_DRIVING_CTRL = 0x02;
constexpr uint8_t ILI9225_ENTRY_MODE = 0x03;
constexpr uint8_t ILI9225_DISP_CTRL1 = 0x07;
constexpr uint8_t ILI9225_BLANK_PERIOD_CTRL1 = 0x08;
constexpr uint8_t ILI9225_FRAME_CYCLE_CTRL = 0x0B;
constexpr uint8_t ILI9225_INTERFACE_CTRL = 0x0C;
constexpr uint8_t ILI9225_OSC_CTRL = 0x0F;
constexpr uint8_t ILI9225_POWER_CTRL1 = 0x10;
constexpr uint8_t ILI9225_POWER_CTRL2 = 0x11;
constexpr uint8_t ILI9225_POWER_CTRL3 = 0x12;
constexpr uint8_t ILI9225_POWER_CTRL4 = 0x13;
constexpr uint8_t ILI9225_POWER_CTRL5 = 0x14;
constexpr uint8_t ILI9225_VCI_RECYCLING = 0x15;
constexpr uint8_t ILI9225_RAM_ADDR_SET1 = 0x20;
constexpr uint8_t ILI9225_RAM_ADDR_SET2 = 0x21;
constexpr uint8_t ILI9225_GRAM_DATA_REG = 0x22;
constexpr uint8_t ILI9225_GATE_SCAN_CTRL = 0x30;
constexpr uint8_t ILI9225_VERTICAL_SCROLL_CTRL1 = 0x31;
constexpr uint8_t ILI9225_VERTICAL_SCROLL_CTRL2 = 0x32;
constexpr uint8_t ILI9225_VERTICAL_SCROLL_CTRL3 = 0x33;
constexpr uint8_t ILI9225_PARTIAL_DRIVING_POS1 = 0x34;
constexpr uint8_t ILI9225_PARTIAL_DRIVING_POS2 = 0x35;
constexpr uint8_t ILI9225_HORIZONTAL_WINDOW_ADDR1 = 0x36;
constexpr uint8_t ILI9225_HORIZONTAL_WINDOW_ADDR2 = 0x37;
constexpr uint8_t ILI9225_VERTICAL_WINDOW_ADDR1 = 0x38;
constexpr uint8_t ILI9225_VERTICAL_WINDOW_ADDR2 = 0x39;
constexpr uint8_t ILI9225_GAMMA_CTRL1 = 0x50;
constexpr uint8_t ILI9225_GAMMA_CTRL2 = 0x51;
constexpr uint8_t ILI9225_GAMMA_CTRL3 = 0x52;
constexpr uint8_t ILI9225_GAMMA_CTRL4 = 0x53;
constexpr uint8_t ILI9225_GAMMA_CTRL5 = 0x54;
constexpr uint8_t ILI9225_GAMMA_CTRL6 = 0x55;
constexpr uint8_t ILI9225_GAMMA_CTRL7 = 0x56;
constexpr uint8_t ILI9225_GAMMA_CTRL8 = 0x57;
constexpr uint8_t ILI9225_GAMMA_CTRL9 = 0x58;
constexpr uint8_t ILI9225_GAMMA_CTRL10 = 0x59;

// Convert 24 bit RGB colors (RGB888) to 16 bit RGB colors (RGB565)
constexpr uint16_t RGB888_RGB565(uint32_t color) {
    uint8_t r = color >> 16;
    uint8_t g = color >> 8;
    uint8_t b = color;

    // Only pick highest bits for each color
    return ((r >> 3) << (5 + 6)) | ((g >> 2) << 5) | (b >> 3);
}

constexpr uint16_t COLOR_BLACK = RGB888_RGB565(0x000000);
constexpr uint16_t COLOR_WHITE = RGB888_RGB565(0xFFFFFF);
constexpr uint16_t COLOR_RED = RGB888_RGB565(0xFF0000);
constexpr uint16_t COLOR_GREEN = RGB888_RGB565(0x00FF00);
constexpr uint16_t COLOR_BLUE = RGB888_RGB565(0x0000FF);
constexpr uint16_t COLOR_YELLOW = RGB888_RGB565(0xFFFF00);
constexpr uint16_t COLOR_CYAN = RGB888_RGB565(0x00FFFF);
constexpr uint16_t COLOR_ORANGE = RGB888_RGB565(0xFFA500);
constexpr uint16_t COLOR_VIOLET = RGB888_RGB565(0xEE82EE);

// For the font defined in ILI9225.cpp
constexpr uint16_t char_width = 5;
constexpr uint16_t char_height = 8;

namespace Display {
void init();
void clear(uint16_t color = COLOR_BLACK);
void draw_pixel(uint8_t x, uint8_t y, uint16_t color);
void fill_box(uint8_t x0, uint8_t y0, uint8_t x1, uint8_t y1, uint16_t color);
void draw_box(uint8_t x0, uint8_t y0, uint8_t x1, uint8_t y1, uint16_t color);
void draw_line(uint8_t x0, uint8_t y0, uint8_t x1, uint8_t y1, uint16_t color);
void draw_char(unsigned char c, uint8_t x, uint8_t y, uint16_t color,
               uint16_t bg_color = COLOR_BLACK);
void draw_number(uint8_t num, uint8_t x, uint8_t y, uint16_t color,
                 uint16_t bg_color = COLOR_BLACK);
void draw_numbers(uint16_t num, uint8_t n_digits, uint8_t x, uint8_t y,
                  uint16_t color, uint16_t bg_color = COLOR_BLACK);
void draw_text(const char *msg, uint8_t x, uint8_t y, uint16_t color,
               uint16_t bg_color = COLOR_BLACK);
void draw_text_pgm(const char *msg, uint8_t x, uint8_t y, uint16_t color,
                   uint16_t bg_color = COLOR_BLACK);
} // namespace Display
