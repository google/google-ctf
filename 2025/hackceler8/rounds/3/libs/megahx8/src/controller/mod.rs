
pub(crate) mod m68k;

#[repr(u8)]
#[derive(Copy, Clone, Debug)]
pub enum Button {
    Up = 0,
    Down = 1,
    Left = 2,
    Right = 3,
    B = 4,
    C = 5,
    A = 6,
    Start = 7,
    Z = 8,
    Y = 9,
    X = 10,
    Mode = 11,
}

pub trait ControllerState {
    /// Returns true if this is a 6 button controller.
    fn is_6button(&self) -> bool;

    /// Returns true if a given button is pressed.
    fn is_pressed(&self, btn: Button) -> bool;

    /// Returns true if a given button was pressed this frame.
    fn just_pressed(&self, btn: Button) -> bool;
}

pub trait Controllers {
    /// Fetch the controller state for a single controller.
    fn controller_state(&self, controller_idx: usize) -> Option<&dyn ControllerState>;

    /// Update the state of the controllers.
    ///
    /// This should only be called once per `VBlank`. Calling it too frequently
    /// can result in incorrect results.
    fn update(&mut self);
}
