// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the License);
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an AS IS BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use heapless::String;
use heapless::Vec;
use megahx8::*;

use crate::game::Ctx;
use crate::image::Image;
use crate::UI;

const FRAMES_PER_CHARS: u16 = 4; // Render a char every 4 frames (15 chars per second).
const TEXT_START_X: u16 = 5;
const TEXT_START_Y: u16 = 15;
const TEXT_WIDTH: u16 = 30;
const TEXT_HEIGHT: u16 = 10;
/// List of characters that can be input as a free text input, in their order of appearance.
const FREE_TEXT_CHARS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~0123456789 ";

pub struct Dialogue {
    /// Text to render.
    text: String<512>,
    /// Data about the player's response.
    response: ResponseType,
    /// Function to call after the dialogue has finished.
    pub on_finish: Option<fn(ctx: &mut Ctx, response: &str)>,
    frame: u16,
    render_state: RenderState,
}

enum ResponseType {
    /// No response needed.
    None,
    /// Player selects between predefined options.
    MultipleChoice {
        choices: Vec<String<32>, 8>,
        selection: usize,
    },
    /// Player can enter arbitrary text.
    FreeText {
        text: String<{ TEXT_WIDTH as usize }>,
        charset: String<100>,
    },
}

struct RenderState {
    first_render: bool,
    /// Current and previous progress in rendering the dialogue text.
    prev_text_progress: u16,
    text_progress: u16,
    /// Coordinates of the next char to render.
    next_x: u16,
    next_y: u16,
    /// Whether all of the text has been rendered.
    text_complete: bool,
}

impl Dialogue {
    /// Initializes a dialogue object that doesn't accept any player response
    /// (just prints the text and exits).
    pub fn new_no_response(
        text: &str,
        on_finish: Option<fn(ctx: &mut Ctx, response: &str)>,
    ) -> Dialogue {
        Self::new(text, on_finish, ResponseType::None)
    }

    /// Initializes a dialogue object that accepts multiple choices responses
    /// (picking an option from a predefined list).
    pub fn new_multiple_choice(
        text: &str,
        choices: &[&str],
        on_finish: Option<fn(ctx: &mut Ctx, response: &str)>,
    ) -> Dialogue {
        let mut choice_vec = Vec::new();
        for c in choices {
            choice_vec
                .push(String::try_from(*c).unwrap_or_else(|_| panic!("choice text too big")))
                .unwrap_or_else(|_| panic!("choices list too big"));
        }
        Self::new(
            text,
            on_finish,
            ResponseType::MultipleChoice {
                choices: choice_vec,
                selection: 0,
            },
        )
    }

    /// Initializes a dialogue object that accepts free text input
    /// (players can write text from a set of allowed characters).
    pub fn new_free_text(
        text: &str,
        on_finish: Option<fn(ctx: &mut Ctx, response: &str)>,
    ) -> Dialogue {
        let charset =
            String::try_from(FREE_TEXT_CHARS).unwrap_or_else(|_| panic!("charset too big"));
        let mut response = String::new();
        // Start the response text with the 1st char pre-set to the 1st option from the char list.
        response.push(charset.chars().next().unwrap()).unwrap();
        Self::new(
            text,
            on_finish,
            ResponseType::FreeText {
                text: response,
                charset,
            },
        )
    }

    /// Initializes a dialogue object that accepts free text input
    /// with a restricted set of characters.
    pub fn new_free_text_restricted_charset(
        text: &str,
        charset: &str,
        on_finish: Option<fn(ctx: &mut Ctx, response: &str)>,
    ) -> Dialogue {
        let charset = String::try_from(charset).unwrap_or_else(|_| panic!("charset too big"));
        let mut response = String::new();
        response.push(charset.chars().next().unwrap()).unwrap();
        Self::new(
            text,
            on_finish,
            ResponseType::FreeText {
                text: response,
                charset,
            },
        )
    }

    fn new(
        text: &str,
        on_finish: Option<fn(ctx: &mut Ctx, response: &str)>,
        response: ResponseType,
    ) -> Dialogue {
        Self {
            text: String::try_from(text).unwrap(),
            response,
            on_finish,
            frame: 0,
            render_state: RenderState {
                first_render: true,
                prev_text_progress: 0,
                text_progress: 0,
                next_x: 0,
                next_y: 0,
                text_complete: false,
            },
        }
    }

    /// Returns the player's response if the dialogue has finished.
    pub fn update(ctx: &mut Ctx) -> Option<String<32>> {
        let b_pressed = Self::btn_pressed(ctx, Button::B);
        let down_pressed = Self::btn_pressed(ctx, Button::Down);
        let up_pressed = Self::btn_pressed(ctx, Button::Up);
        let left_pressed = Self::btn_pressed(ctx, Button::Left);
        let right_pressed = Self::btn_pressed(ctx, Button::Right);

        if let Some(dialogue) = &mut ctx.dialogue {
            dialogue.frame = dialogue.frame.wrapping_add(1);
            if dialogue.render_state.text_complete {
                // Wait for player to close screen or update
                // their response selection.
                dialogue.update_response(
                    down_pressed,
                    up_pressed,
                    left_pressed,
                    right_pressed,
                    &ctx.ui,
                    &mut ctx.vdp,
                );
                if b_pressed {
                    // Exit dialogue screen and return player's response.
                    return match &dialogue.response {
                        ResponseType::None => Some(String::new()),
                        ResponseType::MultipleChoice { choices, selection } => {
                            Some(choices[*selection].clone())
                        }
                        ResponseType::FreeText { text, .. } => {
                            let mut res = String::new();
                            let _ = res.push_str(&text);
                            Some(res)
                        }
                    };
                }
            } else if b_pressed {
                // Skip through dialogue.
                dialogue.render_state.text_progress = dialogue.text.len() as u16;
            } else if dialogue.frame % FRAMES_PER_CHARS == 0 {
                dialogue.render_state.text_progress += 1;
            }
        }

        None
    }

    pub fn render(&mut self, ui: &UI, vdp: &mut TargetVdp) {
        self.render_border(ui, vdp);
        self.render_text(ui, vdp);
    }

    pub fn clear(vdp: &mut TargetVdp) {
        for x in 0..TEXT_WIDTH + 2 {
            for y in 0..TEXT_HEIGHT + 2 {
                Image::clear_tile(TEXT_START_X + x - 1, TEXT_START_Y + y - 1, vdp);
            }
        }
    }

    fn render_border(&mut self, ui: &UI, vdp: &mut TargetVdp) {
        if !self.render_state.first_render {
            return;
        }
        self.render_state.first_render = false;

        for x in 0..TEXT_WIDTH + 2 {
            for y in 0..TEXT_HEIGHT + 2 {
                // Select correct border side
                const END_X: u16 = TEXT_WIDTH + 1;
                const END_Y: u16 = TEXT_HEIGHT + 1;
                let tile_num = match (x, y) {
                    // Edges
                    (0, 0) => 0,
                    (0, END_Y) => 6,
                    (END_X, 0) => 2,
                    (END_X, END_Y) => 8,
                    // Faces
                    (0, _) => 3,
                    (END_X, _) => 5,
                    (_, 0) => 1,
                    (_, END_Y) => 7,
                    // Middle
                    _ => 4,
                };
                Image::draw_tile(
                    &ui.inventory_border_img,
                    tile_num,
                    TEXT_START_X + x - 1,
                    TEXT_START_Y + y - 1,
                    vdp,
                );
            }
        }
    }

    fn render_text(&mut self, ui: &UI, vdp: &mut TargetVdp) {
        if self.render_state.text_complete {
            return;
        }
        for p in self.render_state.prev_text_progress..self.render_state.text_progress {
            if p as usize == self.text.len() {
                self.render_state.text_complete = true;
                self.render_response_input(ui, vdp);
                break;
            }
            let chr = self.text.chars().nth(p as usize).unwrap();
            if chr == '\n' {
                self.render_state.next_x = 0;
                self.render_state.next_y += 1;
            } else if chr == ' ' && self.next_word_end(p as usize + 1) >= TEXT_WIDTH {
                // Wrap words that overflow into the next line.
                self.render_state.next_x = 0;
                self.render_state.next_y += 1;
            } else {
                if self.render_state.next_x >= TEXT_WIDTH {
                    // Start a new line.
                    self.render_state.next_x = 0;
                    self.render_state.next_y += 1;
                    if chr == ' ' {
                        // Don't print wrapped spaces.
                        continue;
                    }
                }
                UI::draw_text_char(
                    chr as u8,
                    TEXT_START_X + self.render_state.next_x,
                    TEXT_START_Y + self.render_state.next_y,
                    &ui.inventory_text_img,
                    vdp,
                );
                self.render_state.next_x += 1;
            }
        }
        self.render_state.prev_text_progress = self.render_state.text_progress;
    }

    /// Render UI for player response (e.g. multiple choice options).
    fn render_response_input(&mut self, ui: &UI, vdp: &mut TargetVdp) {
        match &self.response {
            ResponseType::None => {}
            ResponseType::MultipleChoice { choices, .. } => {
                for c in 0..choices.len() {
                    let (x, y) = Self::get_choice_text_pos(choices, c as u16);
                    UI::draw_text(&choices[c], x, y, &ui.inventory_text_img, vdp);
                }
                // Draw choice arrow.
                let (x, y) = Self::get_choice_text_pos(choices, 0);
                Image::draw(&ui.choice_arrow_img, x - 1, y, vdp);
            }
            ResponseType::FreeText { text, .. } => {
                // Render free text input UI:
                // A_____________________________
                // ^
                UI::draw_text_char(
                    text.chars().next().unwrap() as u8,
                    TEXT_START_X,
                    TEXT_START_Y + TEXT_HEIGHT - 1,
                    &ui.inventory_text_img,
                    vdp,
                );
                for x in TEXT_START_X + 1..TEXT_START_X + TEXT_WIDTH {
                    UI::draw_text(
                        "_",
                        x,
                        TEXT_START_Y + TEXT_HEIGHT - 1,
                        &ui.inventory_text_img,
                        vdp,
                    );
                }
                Image::draw(
                    &ui.text_arrow_img,
                    TEXT_START_X,
                    TEXT_START_Y + TEXT_HEIGHT,
                    vdp,
                );
            }
        };
    }

    /// Returns the render position, in tiles, of the choice text at the specified index.
    fn get_choice_text_pos(choices: &Vec<String<32>, 8>, choice_idx: u16) -> (u16, u16) {
        // Draw choice texts in 2 columns at the bottom of the textbox.
        let x = TEXT_START_X + (choice_idx % 2) * (TEXT_WIDTH / 2) + 1;
        let choices_height = (choices.len() / 2 + choices.len() % 2) as u16;
        let y = TEXT_START_Y + TEXT_HEIGHT - choices_height + choice_idx / 2;
        (x, y)
    }

    /// Update the response based on the pressed keys and response type,
    /// e.g. move the selected multiple choice options.
    fn update_response(
        &mut self,
        down_pressed: bool,
        up_pressed: bool,
        left_pressed: bool,
        right_pressed: bool,
        ui: &UI,
        vdp: &mut TargetVdp,
    ) {
        match &mut self.response {
            ResponseType::None => {}
            ResponseType::MultipleChoice { choices, selection } => {
                if !down_pressed && !up_pressed && !left_pressed && !right_pressed {
                    return;
                }
                let (prev_x, prev_y) = Self::get_choice_text_pos(choices, *selection as u16);
                // Clear by filling with black tile.
                Image::draw_tile(&ui.inventory_border_img, 4, prev_x - 1, prev_y, vdp);

                // Choice ordering:
                // 0 1
                // 2 3
                // ...
                if down_pressed && *selection < choices.len() - 2 {
                    *selection += 2;
                } else if up_pressed && *selection > 1 {
                    *selection -= 2;
                } else if right_pressed && *selection < choices.len() - 1 {
                    *selection += 1;
                } else if left_pressed && *selection > 0 {
                    *selection -= 1;
                }

                let (new_x, new_y) = Self::get_choice_text_pos(choices, *selection as u16);
                Image::draw(&ui.choice_arrow_img, new_x - 1, new_y, vdp);
            }
            ResponseType::FreeText { text, charset } => {
                let x = TEXT_START_X + text.len() as u16 - 1;
                let y = TEXT_START_Y + TEXT_HEIGHT - 1;
                if up_pressed || down_pressed {
                    // Cycle through chars to input.
                    if let Some(chr) = text.pop() {
                        let mut pos = charset.chars().position(|c| c == chr).unwrap();
                        if up_pressed {
                            pos = if pos >= charset.len() - 1 { 0 } else { pos + 1 };
                        } else {
                            pos = if pos == 0 { charset.len() - 1 } else { pos - 1 };
                        }
                        let new_chr = charset.chars().nth(pos).unwrap();
                        text.push(new_chr).unwrap();
                        UI::draw_text_char(new_chr as u8, x, y, &ui.inventory_text_img, vdp);
                    }
                } else if right_pressed && text.len() < text.capacity() {
                    // Add a new char.
                    let new_chr = charset.chars().next().unwrap();
                    text.push(new_chr).unwrap();
                    UI::draw_text_char(new_chr as u8, x + 1, y, &ui.inventory_text_img, vdp);

                    if x < TEXT_START_X + TEXT_WIDTH - 1 {
                        // Clear previous arrow.
                        if x >= TEXT_START_X {
                            Image::draw_tile(&ui.inventory_border_img, 7, x, y + 1, vdp);
                        }
                        // Add new arrow.
                        Image::draw(&ui.text_arrow_img, x + 1, y + 1, vdp);
                    }
                } else if left_pressed {
                    // Delete current char.
                    text.pop();
                    if x >= TEXT_START_X {
                        UI::draw_text("_", x, y, &ui.inventory_text_img, vdp);
                    }
                    if x < TEXT_START_X + TEXT_WIDTH {
                        // Clear previous arrow.
                        if x >= TEXT_START_X {
                            Image::draw_tile(&ui.inventory_border_img, 7, x, y + 1, vdp);
                        }
                        // Add new arrow.
                        if x > TEXT_START_X {
                            Image::draw(&ui.text_arrow_img, x - 1, y + 1, vdp);
                        }
                    }
                }
            }
        }
    }

    /// Returns the x position of the end of the next word to print.
    fn next_word_end(&self, next_char_pos: usize) -> u16 {
        for pos in next_char_pos..self.text.len() {
            let chr = self.text.chars().nth(pos).unwrap();
            if chr == ' ' || chr == '\n' {
                return self.render_state.next_x + (pos - next_char_pos) as u16;
            }
        }
        return self.render_state.next_x + (self.text.len() - next_char_pos) as u16;
    }

    /// Whether the specified button has been pressed on one of the controllers.
    pub fn btn_pressed(ctx: &mut Ctx, button: Button) -> bool {
        for p in 0..ctx.players.len() {
            // Consider only active players for UI input.
            if !ctx.players[p].active {
                continue;
            }
            if let Some(input) = ctx.controller.controller_state(p) {
                if input.just_pressed(button) {
                    return true;
                }
                // A button can be used to fast-forward.
                if input.is_pressed(Button::A) && input.is_pressed(button) {
                    return true;
                }
            }
        }
        false
    }
}
