use std::collections::HashSet;

use crate::controller::Button;
use crate::controller::ControllerState as ControllerStateTrait;

pub struct ControllerState {
    pub pressed: HashSet<Button>,
    pub just_pressed: HashSet<Button>,
    /// Buffers inputs set between frames so they become `just_pressed` for exactly one frame
    /// during the next update. This prevents asynchronous test inputs from persisting too long.
    pub pending_just_pressed: HashSet<Button>,
    pub is_6button: bool,
}

impl Default for ControllerState {
    fn default() -> Self {
        Self {
            pressed: HashSet::new(),
            just_pressed: HashSet::new(),
            pending_just_pressed: HashSet::new(),
            is_6button: true,
        }
    }
}

impl ControllerStateTrait for ControllerState {
    fn is_6button(&self) -> bool {
        self.is_6button
    }
    fn is_pressed(&self, btn: Button) -> bool {
        self.pressed.contains(&btn)
    }
    fn just_pressed(&self, btn: Button) -> bool {
        self.just_pressed.contains(&btn)
    }
}

pub struct Controllers {
    pub states: [ControllerState; 4],
}

impl Controllers {
    pub fn new() -> Self {
        Self {
            states: Default::default(),
        }
    }

    pub fn set_pressed(&mut self, idx: usize, btn: Button, pressed: bool) {
        if let Some(state) = self.states.get_mut(idx) {
            if pressed {
                state.pressed.insert(btn);
                state.pending_just_pressed.insert(btn);
            } else {
                state.pressed.remove(&btn);
            }
        }
    }

    pub fn clear_just_pressed(&mut self, idx: usize) {
        if let Some(state) = self.states.get_mut(idx) {
            state.just_pressed.clear();
            state.pending_just_pressed.clear();
        }
    }
}

impl crate::controller::Controllers for Controllers {
    fn controller_state(&self, controller_idx: usize) -> Option<&dyn ControllerStateTrait> {
        self.states
            .get(controller_idx)
            .map(|s| s as &dyn ControllerStateTrait)
    }
    fn update(&mut self) {
        for state in &mut self.states {
            state.just_pressed = state.pending_just_pressed.clone();
            state.pending_just_pressed.clear();
        }
    }
}
