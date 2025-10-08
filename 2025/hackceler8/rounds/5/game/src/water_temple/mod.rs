use crate::map::NewFn;

pub mod w00;
pub mod w10;
pub mod w20;
pub mod w01;
pub mod w11;
pub mod w21;
pub mod w02;
pub mod w12;
pub mod w22;
pub mod w03;
pub mod w13;
pub mod w23;
pub mod w04;
pub mod w14;
pub mod w24;
pub mod w05;
pub mod w15;
pub mod w25;


// pub const IDENTIFIER: &str = "water-temple";

// Width of the world in maps
pub const WIDTH: usize = 3;
// Height of the world in maps
pub const HEIGHT: usize = 6;

pub const MAPS: [Option<NewFn>; 3*6] = [
    Some(w00::new),
    Some(w10::new),
    Some(w20::new),
    Some(w01::new),
    Some(w11::new),
    Some(w21::new),
    Some(w02::new),
    Some(w12::new),
    Some(w22::new),
    Some(w03::new),
    Some(w13::new),
    Some(w23::new),
    Some(w04::new),
    Some(w14::new),
    Some(w24::new),
    Some(w05::new),
    Some(w15::new),
    Some(w25::new)
];

pub const START_COORDS: (i16, i16) = (1,5);

pub fn map(x: i16, y: i16) -> Option<NewFn> {
    if x < 0 || y < 0 {
        panic!("Map coordinate underflow");
    }

    let x = x as usize;
    let y = y as usize;

    if x >= WIDTH || y >= HEIGHT {
        panic!("Map coordinate overflow");
    }

    let idx = y * WIDTH + x;

    MAPS[idx]
}

pub fn map_module_name(x: i16, y: i16) -> Option<&'static str> {
    match (x, y) {
        (0, 0) => Some("w00"),
        (1, 0) => Some("w10"),
        (2, 0) => Some("w20"),
        (0, 1) => Some("w01"),
        (1, 1) => Some("w11"),
        (2, 1) => Some("w21"),
        (0, 2) => Some("w02"),
        (1, 2) => Some("w12"),
        (2, 2) => Some("w22"),
        (0, 3) => Some("w03"),
        (1, 3) => Some("w13"),
        (2, 3) => Some("w23"),
        (0, 4) => Some("w04"),
        (1, 4) => Some("w14"),
        (2, 4) => Some("w24"),
        (0, 5) => Some("w05"),
        (1, 5) => Some("w15"),
        (2, 5) => Some("w25"),
        _ => None,
    }
}
