use megahx8::*;
use crate::image::*;
use crate::resource_state::State;
use crate::res::tileset::{{name}}::PALETTE;

pub fn new(state: &mut State, vdp: &mut TargetVdp, keep_loaded: bool) -> Image {
    Image::new(state, vdp, /*tiles_idx=*/{{tiles_idx}}, /*width=*/{{width}}, /*height=*/{{height}}, PALETTE, keep_loaded)
}
