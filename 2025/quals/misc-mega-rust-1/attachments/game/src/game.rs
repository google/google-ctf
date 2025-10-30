// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::flag::Flag;
use crate::map::Map;
use crate::palettes;
use crate::sonk::Sonk;
use crate::spike::Spike;
use crate::tiles;
use crate::wasp::Wasp;
use heapless::Vec;
use megarust::*;

extern "C" {
    fn _start() -> !;
}

#[no_mangle]
static mut GOT_FLAG: u8 = b'0';

struct YouWin {
    frame: u16,
    current_palette: [u16; 16],
}

impl YouWin {
    const WIN_COLORS: [u16; 6] = [0x00F, 0x0FF, 0x0F0, 0xFF0, 0xF00, 0xF0F];
    const DEFAULT_PALETTE: [u16; 16] = [
        0x000, 0xFFF, 0xF00, 0x0F0, 0x00B, 0xFF0, 0xF0F, 0x0FF, 0x666, 0xBBB, 0x800, 0x080, 0x008,
        0x880, 0x808, 0x088,
    ];
    pub(crate) fn new(id: u8, vdp: &mut impl Vdp) -> Self {
        vdp.wait_for_vblank();
        unsafe {
            vdp.reset_state();
        }
        vdp.set_plane_size(ScrollSize::Cell64, ScrollSize::Cell32);
        vdp.set_h_scroll(0, &[0, 0]);
        vdp.set_v_scroll(0, &[0, 0]);
        DEFAULT_FONT_1X1.load(vdp);

        vdp.set_palette(Palette::A, &Self::DEFAULT_PALETTE);
        vdp.set_background(Palette::A, 0);

        let txt = &[
            b'Y', b'o', b'u', b' ', b'g', b'o', b't', b' ', b'f', b'l', b'a', b'g', b' ', id, b'!',
        ];
        DEFAULT_FONT_1X1.blit_text_bytes_to_plane(Plane::A, vdp, txt, 14 * 64 + 12);

        unsafe {
            GOT_FLAG = id;
        }

        Self {
            frame: 0,
            current_palette: Self::DEFAULT_PALETTE,
        }
    }

    pub(crate) fn update(&mut self) {
        self.frame += 1;
        for i in 1..16 {
            self.current_palette[i] =
                Self::WIN_COLORS[(i + (self.frame as usize) / 10) % Self::WIN_COLORS.len()];
        }
    }

    pub(crate) fn render(&mut self, vdp: &mut impl Vdp) {
        vdp.set_palette(Palette::A, &self.current_palette);
    }
}

pub struct Game<C: Controllers, R: Renderer, V: Vdp> {
    pub vdp: V,
    renderer: R,
    pub controller: C,
    pub frame: u16,
    sonk: Sonk,
    flags: Vec<Flag, 2>,
    wasps: Vec<Wasp, 256>,
    spikes: Vec<Spike, 64>,
    map: Map,
    win_scene: Option<YouWin>,
}

impl Game<TargetControllers, TargetRenderer, TargetVdp> {
    pub fn new(
        mut vdp: TargetVdp,
        renderer: TargetRenderer,
        controller: TargetControllers,
    ) -> Self {
        vdp.enable_interrupts(false, true, false);
        vdp.set_scroll_base(0xA800);
        vdp.set_sprite_address(0xBC00);
        vdp.set_plane_b_address(0xC000);
        vdp.set_plane_a_address(0xE000);
        vdp.set_window_base(0xF000);
        vdp.enable_display(true);
        vdp.set_plane_size(ScrollSize::Cell64, ScrollSize::Cell32);
        vdp.set_scroll_mode(HScrollMode::FullScroll, VScrollMode::FullScroll);
        vdp.set_h_scroll(0, &[0, 0]);
        vdp.set_v_scroll(0, &[0, 0]);
        palettes::init(&mut vdp);
        tiles::init(&mut vdp);
        let map = Map::new();
        map.load_bg(&mut vdp);
        let mut flags = Vec::new();
        flags
            .push(Flag::new(b'A', 4929, 672))
            .map_err(|_| "onoez")
            .unwrap();
        flags
            .push(Flag::new(b'B', 2911, 136))
            .map_err(|_| "onoez")
            .unwrap();
        Game {
            vdp,
            renderer,
            controller,
            frame: 0,
            sonk: Sonk::new(),
            flags,
            wasps: Vec::new(),
            spikes: Vec::new(),
            map,
            win_scene: None,
        }
    }

    pub fn update(&mut self) {
        self.controller.update();
        if let Some(scene) = self.win_scene.as_mut() {
            scene.update();
        } else {
            self.frame = self.frame.wrapping_add(1);
            self.sonk
                .update(&self.map, &mut self.vdp, &mut self.controller, self.frame);
            self.wasps
                .retain(|w| Wasp::on_screen(w.sprite.x as i16, w.sprite.y as i16));
            self.spikes
                .retain(|w| Spike::on_screen(w.sprite.x as i16, w.sprite.y as i16));
            for flag in &mut self.flags.iter_mut() {
                if flag.update(&self.sonk, self.frame) {
                    self.win_scene = Some(YouWin::new(flag.id, &mut self.vdp));
                    return;
                }
            }
            for wasp in &mut self.wasps.iter_mut() {
                wasp.update(&mut self.sonk);
            }
            for spike in &mut self.spikes.iter_mut() {
                spike.update(&mut self.sonk, self.frame);
            }
            self.update_camera();
        }
    }

    pub fn draw(&mut self) {
        self.renderer.clear();
        if let Some(scene) = self.win_scene.as_mut() {
            scene.render(&mut self.vdp);
        } else {
            self.sonk.render(self.frame, &mut self.renderer);
            for flag in &mut self.flags.iter_mut() {
                flag.render(&mut self.renderer);
            }
            for wasp in &mut self.wasps.iter_mut() {
                wasp.render(&mut self.renderer);
            }
            for spike in &mut self.spikes.iter_mut() {
                spike.render(&mut self.renderer);
            }
        }

        self.renderer.render(&mut self.vdp);

        // vsync
        self.vdp.wait_for_vblank();
    }

    fn update_camera(&mut self) {
        let mut dx = 0i16;
        if self.sonk.speed_x > 0 && self.sonk.sprite.x > 128 + 250 - 32 {
            dx = self.sonk.sprite.x as i16 - (128 + 250 - 32);
        } else if self.sonk.speed_x < 0 && self.sonk.sprite.x < 128 + 70 {
            dx = self.sonk.sprite.x as i16 - (128 + 70);
        }
        dx = self.map.scroll_bg_x(&mut self.vdp, dx);

        let mut dy = 0i16;
        if self.sonk.speed_y > 0 && self.sonk.sprite.y > 128 + 154 - 32 {
            dy = self.sonk.sprite.y as i16 - (128 + 154 - 32);
        } else if self.sonk.speed_y < 0 && self.sonk.sprite.y < 128 + 70 {
            dy = self.sonk.sprite.y as i16 - (128 + 70);
        }
        dy = self.map.scroll_bg_y(&mut self.vdp, dy);

        self.sonk.sprite.x = (self.sonk.sprite.x as i16 - dx).min(320 + 128 + 64).max(64) as u16;
        self.sonk.sprite.y = (self.sonk.sprite.y as i16 - dy).min(224 + 128 + 64).max(64) as u16;

        for flag in &mut self.flags.iter_mut() {
            flag.x = (flag.x as i16 - dx) as u16;
            flag.y = (flag.y as i16 - dy) as u16;
            flag.sprite.x = flag.x.min(320 + 128 + 64).max(64);
            flag.sprite.y = flag.y.min(224 + 128 + 64).max(64);
        }

        for wasp in &mut self.wasps.iter_mut() {
            wasp.sprite.x = (wasp.sprite.x as i16 - dx) as u16;
            wasp.sprite.y = (wasp.sprite.y as i16 - dy) as u16;
        }
        self.map.add_new_wasps(dx, dy, &mut self.wasps);

        for spike in &mut self.spikes.iter_mut() {
            spike.sprite.x = (spike.sprite.x as i16 - dx) as u16;
            spike.sprite.y = (spike.sprite.y as i16 - dy) as u16;
        }
        self.map.add_new_spikes(dx, dy, &mut self.spikes);
    }
}

#[no_mangle]
pub extern "C" fn game_main() -> ! {
    let (vdp, renderer, controller) = init_hardware();
    let mut game = Game::new(vdp, renderer, controller);
    loop {
        game.update();
        game.draw();
    }
}
