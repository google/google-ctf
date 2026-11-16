# -p game: builds (only) the game crate
# --features tests: enables all the test modules in the codebase
# -- --nocapture: allows the test output to be printed to the console
cargo test -p game --features tests -- --nocapture
