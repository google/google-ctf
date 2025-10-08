use std::env::current_dir;
use std::path::PathBuf;

use convert::GamePalette;

/// Gets the repository root
pub fn repository_root_dir() -> PathBuf {
    let cwd = current_dir().expect("Could not find own path");
    let root = cwd
        .join("../")
        .canonicalize()
        .expect("Could not get parent directory");
    assert!(
        root.join("game").is_dir(),
        "We're in the wrong folder! Make sure you run convert in ./targets/<debug/release>. Ended up in {root:?} | {:?}",
        std::env::current_dir()
    );
    root
}

/// The root the output resources (as rust files) are written to
pub fn output_dir() -> PathBuf {
    repository_root_dir().join("game/src/res").to_path_buf()
}

/// Input resources
pub fn resources_root() -> PathBuf {
    repository_root_dir().join("resources").to_path_buf()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Monitor resources and rerun build.rs if needed.
    println!("cargo::rerun-if-changed=../resources");
    let mut converter = convert::Converter::new(output_dir());

    // List of static images.
    let image_list = [
        (
            resources_root().join("ui/text.png"),
            &GamePalette::UI.global(),
        ),
        (
            resources_root().join("ui/heart.png"),
            &GamePalette::UI.global(),
        ),
        (
            resources_root().join("ui/health-bar.png"),
            &GamePalette::UI.global(),
        ),
        (
            resources_root().join("ui/flag.png"),
            &GamePalette::UI.global(),
        ),
        (
            resources_root().join("ui/inventory-border.png"),
            &GamePalette::UI.global(),
        ),
        (
            resources_root().join("ui/inventory-border-selected.png"),
            &GamePalette::UI.global(),
        ),
        (
            resources_root().join("ui/inventory-text.png"),
            &GamePalette::UI.global(),
        ),
        (
            resources_root().join("ui/choice-arrow.png"),
            &GamePalette::UI.global(),
        ),
        (
            resources_root().join("ui/text-arrow.png"),
            &GamePalette::UI.global(),
        ),
        (
            resources_root().join("ui/game-over.png"),
            &GamePalette::UI.global(),
        ),
    ];

    // List of sprites. Do not use map tilesets here.
    let sprite_list = [
        (
            resources_root().join("sprites/player/player-base.tsx"),
            &GamePalette::Player.global(),
        ),
        (
            resources_root().join("sprites/player/player-team1.tsx"),
            &GamePalette::Player.global(),
        ),
        (
            resources_root().join("sprites/player/player-team2.tsx"),
            &GamePalette::Player.global(),
        ),
        (
            resources_root().join("sprites/player/player-team3.tsx"),
            &GamePalette::Player.global(),
        ),
        (
            resources_root().join("sprites/player/player-team4.tsx"),
            &GamePalette::Player.global(),
        ),
        (
            resources_root().join("sprites/player/player-team5.tsx"),
            &GamePalette::Player.global(),
        ),
        (
            resources_root().join("sprites/player/player-team6.tsx"),
            &GamePalette::Player.global(),
        ),
        (
            resources_root().join("sprites/player/player-team7.tsx"),
            &GamePalette::Player.global(),
        ),
        (
            resources_root().join("sprites/player/player-team8.tsx"),
            &GamePalette::Player.global(),
        ),
        (
            resources_root().join("sprites/player/hat-base.tsx"),
            &GamePalette::Player.global(),
        ),
        (
            resources_root().join("sprites/player/hat-team1.tsx"),
            &GamePalette::Player.global(),
        ),
        (
            resources_root().join("sprites/player/hat-team2.tsx"),
            &GamePalette::Player.global(),
        ),
        (
            resources_root().join("sprites/player/hat-team3.tsx"),
            &GamePalette::Player.global(),
        ),
        (
            resources_root().join("sprites/player/hat-team4.tsx"),
            &GamePalette::Player.global(),
        ),
        (
            resources_root().join("sprites/player/hat-team5.tsx"),
            &GamePalette::Player.global(),
        ),
        (
            resources_root().join("sprites/player/hat-team6.tsx"),
            &GamePalette::Player.global(),
        ),
        (
            resources_root().join("sprites/player/hat-team7.tsx"),
            &GamePalette::Player.global(),
        ),
        (
            resources_root().join("sprites/player/hat-team8.tsx"),
            &GamePalette::Player.global(),
        ),
        (
            resources_root().join("sprites/switch.tsx"),
            &GamePalette::Player.global(),
        ),
        (
            resources_root().join("sprites/chest-npc.tsx"),
            &GamePalette::Player.global(),
        ),
        (
            resources_root().join("sprites/mimic-npc.tsx"),
            &GamePalette::Player.global(),
        ),
        (
            resources_root().join("sprites/items/heart-item.tsx"),
            &GamePalette::Player.global(),
        ),
        (
            resources_root().join("sprites/items/key.tsx"),
            &GamePalette::Player.global(),
        ),
        (
            resources_root().join("sprites/items/goggles.tsx"),
            &GamePalette::Player.global(),
        ),
        (
            resources_root().join("sprites/items/sword.tsx"),
            &GamePalette::Player.global(),
        ),
        (
            resources_root().join("sprites/items/boots.tsx"),
            &GamePalette::Player.global(),
        ),
        (
            resources_root().join("sprites/items/bunnic8or.tsx"),
            &GamePalette::Player.global(),
        ),
        (
            resources_root().join("sprites/crown.tsx"),
            &GamePalette::Player.global(),
        ),
        (
            resources_root().join("sprites/fall.tsx"),
            &GamePalette::Player.global(),
        ),
        (
            resources_root().join("sprites/grey-door-h.tsx"),
            &GamePalette::Background.for_world("overworld"),
        ),
        (
            resources_root().join("sprites/grey-door-v.tsx"),
            &GamePalette::Background.for_world("overworld"),
        ),
        (
            resources_root().join("sprites/rabbit.tsx"),
            &GamePalette::Player.global(),
        ),
        (
            resources_root().join("sprites/dog-npc.tsx"),
            &GamePalette::Enemy.for_world("overworld"),
        ),
        (
            resources_root().join("sprites/blue-door-h.tsx"),
            &GamePalette::Background.for_world("water-temple"),
        ),
        (
            resources_root().join("sprites/blue-door-v.tsx"),
            &GamePalette::Background.for_world("water-temple"),
        ),
        (
            resources_root().join("sprites/octopus.tsx"),
            &GamePalette::Enemy.for_world("water-temple"),
        ),
        (
            resources_root().join("sprites/siren.tsx"),
            &GamePalette::Enemy.for_world("water-temple"),
        ),
        (
            resources_root().join("sprites/duck-npc.tsx"),
            &GamePalette::Enemy.for_world("water-temple"),
        ),
        (
            resources_root().join("sprites/green-door-h.tsx"),
            &GamePalette::Background.for_world("forest-temple"),
        ),
        (
            resources_root().join("sprites/green-door-v.tsx"),
            &GamePalette::Background.for_world("forest-temple"),
        ),
        (
            resources_root().join("sprites/orc.tsx"),
            &GamePalette::Enemy.for_world("forest-temple"),
        ),
        (
            resources_root().join("sprites/goblin.tsx"),
            &GamePalette::Enemy.for_world("forest-temple"),
        ),
        (
            resources_root().join("sprites/racoon-npc.tsx"),
            &GamePalette::Enemy.for_world("forest-temple"),
        ),
        (
            resources_root().join("sprites/red-door-h.tsx"),
            &GamePalette::Background.for_world("fire-temple"),
        ),
        (
            resources_root().join("sprites/red-door-v.tsx"),
            &GamePalette::Background.for_world("fire-temple"),
        ),
        (
            resources_root().join("sprites/blob.tsx"),
            &GamePalette::Enemy.for_world("fire-temple"),
        ),
        (
            resources_root().join("sprites/flameboi.tsx"),
            &GamePalette::Enemy.for_world("fire-temple"),
        ),
        (
            resources_root().join("sprites/cat-npc.tsx"),
            &GamePalette::Enemy.for_world("fire-temple"),
        ),
        (
            resources_root().join("sprites/fireball.tsx"),
            &GamePalette::Enemy.for_world("fire-temple"),
        ),
        (
            resources_root().join("sprites/white-door-h.tsx"),
            &GamePalette::Background.for_world("sky-temple"),
        ),
        (
            resources_root().join("sprites/white-door-v.tsx"),
            &GamePalette::Background.for_world("sky-temple"),
        ),
        (
            resources_root().join("sprites/archer.tsx"),
            &GamePalette::Enemy.for_world("sky-temple"),
        ),
        (
            resources_root().join("sprites/angel.tsx"),
            &GamePalette::Enemy.for_world("sky-temple"),
        ),
        (
            resources_root().join("sprites/snake-npc.tsx"),
            &GamePalette::Enemy.for_world("sky-temple"),
        ),
        (
            resources_root().join("sprites/arrow.tsx"),
            &GamePalette::Enemy.for_world("sky-temple"),
        ),
        (
            resources_root().join("sprites/boss.tsx"),
            &GamePalette::Enemy.for_world("boss-temple"),
        ),
        (
            resources_root().join("sprites/swirl.tsx"),
            &GamePalette::Enemy.for_world("boss-temple"),
        ),
        (
            resources_root().join("sprites/angel-minion.tsx"),
            &GamePalette::Enemy.for_world("boss-temple"),
        ),
        (
            resources_root().join("sprites/orc-minion.tsx"),
            &GamePalette::Enemy.for_world("boss-temple"),
        ),
        (
            resources_root().join("sprites/explosion.tsx"),
            &GamePalette::Enemy.for_world("boss-temple"),
        ),
    ];

    // List of worlds.
    let overworld = convert::World::new(
        resources_root()
            .join("maps")
            .join("overworld")
            .join("overworld.world"),
        "overworld".to_string(),
    )
    .expect("Loading overworld failed");
    let fire_temple = convert::World::new(
        resources_root()
            .join("maps")
            .join("fire-temple")
            .join("fire-temple.world"),
        "fire-temple".to_string(),
    )
    .expect("Loading fire-temple failed");
    let forest_temple = convert::World::new(
        resources_root()
            .join("maps")
            .join("forest-temple")
            .join("forest-temple.world"),
        "forest-temple".to_string(),
    )
    .expect("Loading forest-temple failed");
    let water_temple = convert::World::new(
        resources_root()
            .join("maps")
            .join("water-temple")
            .join("water-temple.world"),
        "water-temple".to_string(),
    )
    .expect("Loading water-temple failed");
    let sky_temple = convert::World::new(
        resources_root()
            .join("maps")
            .join("sky-temple")
            .join("sky-temple.world"),
        "sky-temple".to_string(),
    )
    .expect("Loading water-temple failed");
    let boss_temple = convert::World::new(
        resources_root()
            .join("maps")
            .join("boss-temple")
            .join("boss-temple.world"),
        "boss-temple".to_string(),
    )
    .expect("Loading boss-temple failed");

    // Remove previous directory if it exists.
    let _ = std::fs::remove_dir_all(output_dir());
    std::fs::create_dir_all(output_dir())?;

    // Convert all static images.
    for (file, palette_id) in image_list {
        converter
            .convert_image(file, palette_id)
            .expect("Converting {file} failed");
    }

    // Convert all sprites.
    for (file, palette_id) in sprite_list {
        if let Some(extension) = file.extension() {
            match extension.to_str().unwrap() {
                "tsx" => {
                    converter.convert_sprite(&file, palette_id)?;
                }
                val => {
                    panic!("Bad file suffix {val}, only tsx files are expected.");
                }
            }
        } else {
            panic!("No file suffix!")
        }
    }

    // Convert worlds.
    converter
        .convert_world(&overworld)
        .expect("Converting overworld failed");
    converter
        .convert_world(&fire_temple)
        .expect("Converting fire temple failed");
    converter
        .convert_world(&forest_temple)
        .expect("Converting forest temple failed");
    converter
        .convert_world(&sky_temple)
        .expect("Converting sky temple failed");
    converter
        .convert_world(&water_temple)
        .expect("Converting water temple failed");
    converter
        .convert_world(&boss_temple)
        .expect("Converting boss temple failed");
    converter
        .write_palettes(output_dir().join("palettes.rs"))
        .expect("Writing palettes failed");
    converter
        .write_sprite_mod(output_dir().join("sprites/mod.rs"))
        .expect("Writing sprites/mod.rs failed");
    converter
        .write_tilesets_mod(output_dir().join("tileset/mod.rs"))
        .expect("Writing tileset/mod.rs failed");
    converter
        .write_image_mod(output_dir().join("images/mod.rs"))
        .expect("Writing images/mod.rs failed");
    converter
        .write_map_mod(output_dir().join("maps/mod.rs"))
        .expect("Writing maps/mod.rs failed");
    converter
        .write_main_mod(output_dir().join("mod.rs"))
        .expect("Writing mod.rs failed");
    converter
        .write_enemies(output_dir().join("enemies.rs"))
        .expect("Writing enemies.rs failed");
    converter
        .write_npcs(output_dir().join("npcs.rs"))
        .expect("Writing npcs.rs failed");
    converter
        .write_items(output_dir().join("items.rs"))
        .expect("Writing items.rs failed");
    Ok(())
}
