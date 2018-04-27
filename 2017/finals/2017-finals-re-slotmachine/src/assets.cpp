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



#include "assets.h"

// Contains the RGB888_RGB565 definition the assets use
#include "ILI9225.h"
#include "assets/bar_2c.h"
#include "assets/lemon_3c.h"
#include "assets/seven_2c.h"
#include "gui.h"

// Background related assets
#include "assets/bg_column.h"
#include "assets/bg_jackpot.h"
#include "assets/bg_star.h"
#include "assets/bg_top_bar.h"

#include <avr/pgmspace.h>

namespace Assets {

void draw(const uint16_t *palette, const uint8_t *data, uint8_t x, uint8_t y,
          uint8_t w, uint8_t h, uint8_t bpp, bool mirror_x, bool mirror_y,
          bool has_alpha) {
    // Check for overflow
    if (x + w < x || y + h < y) {
        while (1) {
            // BUG
        }
        return;
    }

    // Start drawing
    // We do assume that the input data is correct.
    // Checks consume time and space and we don't have
    // neither of both.
    uint16_t idx = 0;
    uint8_t current_length = 0;
    uint8_t current_val = 0;
    for (uint8_t yi = 0; yi < h; yi++) {
        for (uint8_t xi = 0; xi < w; xi++) {
            if (!current_length) {
                uint8_t v = pgm_read_byte(data + idx++);
                current_val = v >> (8 - bpp);
                current_length = v & ((1 << (8 - bpp)) - 1);
            }

            if (!has_alpha || current_val) {
                uint8_t off_x;
                uint8_t off_y;
                if (mirror_x) {
                    off_x = w - xi;
                } else {
                    off_x = xi;
                }
                if (mirror_y) {
                    off_y = h - yi;
                } else {
                    off_y = yi;
                }

                uint8_t palette_idx;
                if (has_alpha) {
                    palette_idx = current_val - 1;
                } else {
                    palette_idx = current_val;
                }
                Display::draw_pixel(x + off_x, y + off_y, palette[palette_idx]);
            }
            current_length--;
        }
    }
}

void draw_asset(type_t asset, uint8_t x, uint8_t y, uint8_t w, uint8_t h) {
    uint8_t asset_w = 0, asset_h = 0;
    uint8_t bpp;
    const uint16_t *palette = nullptr;
    const uint8_t *data = nullptr;

    // Get pointers to the asset-to-be-drawn
    switch (asset) {
    case SEVEN:
        asset_w = seven_2c_w;
        asset_h = seven_2c_h;
        palette = seven_2c_palette;
        bpp = seven_2c_bpp;
        data = static_cast<const uint8_t *>(seven_2c_data);
        break;
    case BAR:
        asset_w = bar_2c_w;
        asset_h = bar_2c_h;
        palette = bar_2c_palette;
        bpp = bar_2c_bpp;
        data = static_cast<const uint8_t *>(bar_2c_data);
        break;
    case LEMON:
        asset_w = lemon_3c_w;
        asset_h = lemon_3c_h;
        palette = lemon_3c_palette;
        bpp = lemon_3c_bpp;
        data = static_cast<const uint8_t *>(lemon_3c_data);
        break;
    default:
        return;
    }

    // Make sure there is enough space
    if (w < asset_w || h < asset_h) {
        return;
    }
    // Calculate offsets where to show it
    uint8_t padding_x = (w - asset_w) >> 1;
    uint8_t padding_y = (h - asset_h) >> 1;

    draw(palette, data, x + padding_x, y + padding_y, asset_w, asset_h, bpp,
         false, false, true);
}

void draw_background() {
#define DRAW_ASSET(name, x, y, mx, my, alpha)                                  \
    draw(name##_palette, name##_data, x, y, name##_w, name##_h, name##_bpp,    \
         mx, my, alpha)

    constexpr uint16_t yo = GUI::model_y_offset;
    // Draw top bar
    DRAW_ASSET(bg_top_bar, 0, yo, false, false, true);

    // Columns
    DRAW_ASSET(bg_column, 18, 29 + yo, false, false, false);
    DRAW_ASSET(bg_column, 80, 29 + yo, false, false, false);
    DRAW_ASSET(bg_column, 142, 29 + yo, false, false, false);

    DRAW_ASSET(bg_star, 3, 45 + yo, false, false, true);
    DRAW_ASSET(bg_star, 3, 87 + yo, false, false, true);
    DRAW_ASSET(bg_star, 3, 129 + yo, false, false, true);
    DRAW_ASSET(bg_star, 204, 45 + yo, false, false, true);
    DRAW_ASSET(bg_star, 204, 87 + yo, false, false, true);
    DRAW_ASSET(bg_star, 204, 129 + yo, false, false, true);

#undef DRAW_ASSET
}
} // namespace Assets
