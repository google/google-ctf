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
    println!("cargo::rerun-if-changed=../libs/convert");
    let mut converter = convert::Converter::new(output_dir());

    // List of static images.
    let image_list = [
        (
            resources_root().join("ui/text.png"),
            &GamePalette::UI.default(),
        ),
        (
            resources_root().join("ui/health.png"),
            &GamePalette::UI.default(),
        ),
        (
            resources_root().join("ui/health-bottom.png"),
            &GamePalette::UI.default(),
        ),
        (
            resources_root().join("ui/health-empty.png"),
            &GamePalette::UI.default(),
        ),
        (
            resources_root().join("ui/flag.png"),
            &GamePalette::UI.default(),
        ),
        (
            resources_root().join("ui/inventory-border.png"),
            &GamePalette::UI.default(),
        ),
        (
            resources_root().join("ui/inventory-text.png"),
            &GamePalette::UI.default(),
        ),
        (
            resources_root().join("ui/choice-arrow.png"),
            &GamePalette::UI.default(),
        ),
        (
            resources_root().join("ui/text-arrow.png"),
            &GamePalette::UI.default(),
        ),
        (
            resources_root().join("ui/game-over.png"),
            &GamePalette::UI.for_context("game-over"),
        ),
        (
            resources_root().join("ui/stage-select/stage-select-bg.png"),
            &GamePalette::UI.for_context("stage-select"),
        ),
        (
            resources_root().join("ui/inventory/item_box.png"),
            &GamePalette::Background.for_context("inventory"),
        ),
    ];

    // List of sprites. Do not use map tilesets here.
    let sprite_list = [
        (
            resources_root().join("sprites/player/player.tsx"),
            &GamePalette::Player.for_context("player-shooter"),
        ),
        (
            resources_root().join("sprites/player/player-melee.tsx"),
            &GamePalette::Player.for_context("player-melee"),
        ),
        (
            resources_root().join("sprites/player/player-sword.tsx"),
            &GamePalette::Player.for_context("player-melee"),
        ),
        (
            resources_root().join("sprites/player/player-explosion.tsx"),
            &GamePalette::Player.for_context("player-shooter"),
        ),
        (
            resources_root().join("sprites/player/player-melee-explosion.tsx"),
            &GamePalette::Player.for_context("player-melee"),
        ),
        (
            resources_root().join("sprites/player/player-flamesword.tsx"),
            &GamePalette::Player.for_context("player-melee"),
        ),
        (
            resources_root().join("sprites/player/player-doublesword.tsx"),
            &GamePalette::Player.for_context("player-melee"),
        ),
        (
            resources_root().join("sprites/player/player-strongsword.tsx"),
            &GamePalette::Player.for_context("player-melee"),
        ),
        (
            resources_root().join("sprites/simple_shot.tsx"),
            &GamePalette::Player.for_context("player-shooter"),
        ),
        (
            resources_root().join("sprites/charged_shot.tsx"),
            &GamePalette::Player.for_context("player-shooter"),
        ),
        (
            resources_root().join("sprites/switch.tsx"),
            &GamePalette::UI.default(),
        ),
        (
            resources_root().join("sprites/items/health-item.tsx"),
            &GamePalette::UI.default(),
        ),
        (
            resources_root().join("sprites/items/key.tsx"),
            &GamePalette::UI.default(),
        ),
        (
            resources_root().join("sprites/items/battery.tsx"),
            &GamePalette::UI.default(),
        ),
        (
            resources_root().join("sprites/items/doublejump.tsx"),
            &GamePalette::UI.default(),
        ),
        (
            resources_root().join("sprites/items/walljump.tsx"),
            &GamePalette::UI.default(),
        ),
        (
            resources_root().join("sprites/items/dash.tsx"),
            &GamePalette::UI.default(),
        ),
        (
            resources_root().join("sprites/items/airdash.tsx"),
            &GamePalette::UI.default(),
        ),
        (
            resources_root().join("sprites/rabbit.tsx"),
            &GamePalette::Enemy.for_context("arctic"),
        ),
        (
            resources_root().join("sprites/rabbit-miniboss.tsx"),
            &GamePalette::Enemy.for_context("arctic"),
        ),
        (
            resources_root().join("sprites/dog-npc.tsx"),
            &GamePalette::Enemy.for_context("arctic"),
        ),
        (
            resources_root().join("sprites/octopus.tsx"),
            &GamePalette::Enemy.for_context("arctic"),
        ),
        (
            resources_root().join("sprites/octopus-miniboss.tsx"),
            &GamePalette::Enemy.for_context("arctic"),
        ),
        (
            resources_root().join("sprites/duck-npc.tsx"),
            &GamePalette::Enemy.for_context("arctic"),
        ),
        (
            resources_root().join("sprites/orc.tsx"),
            &GamePalette::Enemy.for_context("forest"),
        ),
        (
            resources_root().join("sprites/orc-miniboss.tsx"),
            &GamePalette::Enemy.for_context("forest"),
        ),
        (
            resources_root().join("sprites/goblin.tsx"),
            &GamePalette::Enemy.for_context("forest"),
        ),
        (
            resources_root().join("sprites/goblin-miniboss.tsx"),
            &GamePalette::Enemy.for_context("forest"),
        ),
        (
            resources_root().join("sprites/racoon-npc.tsx"),
            &GamePalette::Enemy.for_context("forest"),
        ),
        (
            resources_root().join("sprites/red-door-v-animated.tsx"),
            &GamePalette::Background.for_context("volcano"),
        ),
        (
            resources_root().join("sprites/red-door-h-animated.tsx"),
            &GamePalette::Background.for_context("volcano"),
        ),
        (
            resources_root().join("sprites/blue-door-v-animated.tsx"),
            &GamePalette::Background.for_context("arctic"),
        ),
        (
            resources_root().join("sprites/blue-door-h-animated.tsx"),
            &GamePalette::Background.for_context("arctic"),
        ),
        (
            resources_root().join("sprites/green-door-v-animated.tsx"),
            &GamePalette::Background.for_context("forest"),
        ),
        (
            resources_root().join("sprites/green-door-h-animated.tsx"),
            &GamePalette::Background.for_context("forest"),
        ),
        (
            resources_root().join("sprites/white-door-v-animated.tsx"),
            &GamePalette::Background.for_context("spaceship"),
        ),
        (
            resources_root().join("sprites/white-door-h-animated.tsx"),
            &GamePalette::Background.for_context("spaceship"),
        ),
        (
            resources_root().join("sprites/blob.tsx"),
            &GamePalette::Enemy.for_context("volcano"),
        ),
        (
            resources_root().join("sprites/blob-miniboss.tsx"),
            &GamePalette::Enemy.for_context("volcano"),
        ),
        (
            resources_root().join("sprites/flameboi.tsx"),
            &GamePalette::Enemy.for_context("volcano"),
        ),
        (
            resources_root().join("sprites/flameboi-miniboss.tsx"),
            &GamePalette::Enemy.for_context("volcano"),
        ),
        (
            resources_root().join("sprites/cat-npc.tsx"),
            &GamePalette::Enemy.for_context("volcano"),
        ),
        (
            resources_root().join("sprites/fireball.tsx"),
            &GamePalette::Enemy.for_context("volcano"),
        ),
        (
            resources_root().join("sprites/archer.tsx"),
            &GamePalette::Enemy.for_context("spaceship"),
        ),
        (
            resources_root().join("sprites/archer-miniboss.tsx"),
            &GamePalette::Enemy.for_context("spaceship"),
        ),
        (
            resources_root().join("sprites/angel.tsx"),
            &GamePalette::Enemy.for_context("spaceship"),
        ),
        (
            resources_root().join("sprites/angel-miniboss.tsx"),
            &GamePalette::Enemy.for_context("spaceship"),
        ),
        (
            resources_root().join("sprites/snake-npc.tsx"),
            &GamePalette::Enemy.for_context("spaceship"),
        ),
        (
            resources_root().join("sprites/arrow.tsx"),
            &GamePalette::Enemy.for_context("spaceship"),
        ),
        (
            resources_root().join("sprites/boss.tsx"),
            &GamePalette::Enemy.for_context("boss-stage"),
        ),
        (
            resources_root().join("sprites/boss-hand.tsx"),
            &GamePalette::Enemy.for_context("boss-stage"),
        ),
        (
            resources_root().join("sprites/orc-minion.tsx"),
            &GamePalette::Enemy.for_context("boss-stage"),
        ),
        (
            resources_root().join("sprites/explosion.tsx"),
            &GamePalette::Enemy.for_context("boss-stage"),
        ),
        (
            resources_root().join("ui/stage-select/selection.tsx"),
            &GamePalette::Enemy.for_context("stage-select"),
        ),
        (
            resources_root().join("ui/stage-select/level-display.tsx"),
            &GamePalette::Player.for_context("stage-select"),
        ),
    ];

    // List of maps.
    let volcano = convert::Map::new(
        resources_root()
            .join("maps")
            .join("volcano")
            .join("volcano.tmx"),
        "volcano".to_string(),
    );
    let forest = convert::Map::new(
        resources_root()
            .join("maps")
            .join("forest")
            .join("forest.tmx"),
        "forest".to_string(),
    );
    let arctic = convert::Map::new(
        resources_root()
            .join("maps")
            .join("arctic")
            .join("arctic.tmx"),
        "arctic".to_string(),
    );
    let spaceship = convert::Map::new(
        resources_root()
            .join("maps")
            .join("spaceship")
            .join("spaceship.tmx"),
        "spaceship".to_string(),
    );
    let boss_stage = convert::Map::new(
        resources_root()
            .join("maps")
            .join("boss-stage")
            .join("boss-stage.tmx"),
        "boss-stage".to_string(),
    );

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

    // Convert maps.
    converter
        .convert_map(&volcano)
        .expect("Converting fire temple failed");
    converter
        .convert_map(&forest)
        .expect("Converting forest temple failed");
    converter
        .convert_map(&spaceship)
        .expect("Converting sky temple failed");
    converter
        .convert_map(&arctic)
        .expect("Converting water temple failed");
    converter
        .convert_map(&boss_stage)
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
