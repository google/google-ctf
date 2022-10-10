## Game

### How to run

Make sure you have Python3.9 installed and all the packages from `game/requirements.txt` (`python3 -m pip install -r requirements.txt`).
You will also need to install the local version of `pytiled_parser` by moving to the `third_party/pytiled_parser` directory and running `python3 -m pip install .`.

Run server.py in one console and client.py in another.
If you're running the server to code it, you might want to set the
environment variable `UNTRUSTED_SERVER` to `1` to bypass TLS
shenenigans. Moreover, should you encounter unhandled exceptions like 
`AttributeError: 'PersistentState' object has no attribute 'game_complete'`,
delete your `persistence_state` file.

### What's needed to make maps / changes?

You only need [Tiled](https://www.mapeditor.org/) - an open source tile map editor.
The main map is map/map.tmx.

Make sure that you open the tiled project (`map/project.tiled-project`) and not
the map, otherwise the exported map will be broken.

Ensure Tiled Preferences > Export Options have the following options set:
 - Embed tilesets
 - Detach templates
 - Resolve object types and properties

You need to export to `map_exported_main.tmx` for it to be loaded.
(For other maps, export to the appropriately named map_exported_*).
