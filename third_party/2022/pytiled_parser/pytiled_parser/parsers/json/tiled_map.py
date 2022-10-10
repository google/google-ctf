import json
import xml.etree.ElementTree as etree
from pathlib import Path
from typing import List, Union, cast

from typing_extensions import TypedDict

from pytiled_parser.common_types import Size
from pytiled_parser.exception import UnknownFormat
from pytiled_parser.parsers.json.layer import RawLayer
from pytiled_parser.parsers.json.layer import parse as parse_layer
from pytiled_parser.parsers.json.properties import RawProperty
from pytiled_parser.parsers.json.properties import parse as parse_properties
from pytiled_parser.parsers.json.tileset import RawTileSet
from pytiled_parser.parsers.json.tileset import parse as parse_json_tileset
from pytiled_parser.parsers.tmx.tileset import parse as parse_tmx_tileset
from pytiled_parser.tiled_map import TiledMap, TilesetDict
from pytiled_parser.util import check_format, parse_color


class RawTilesetMapping(TypedDict):

    firstgid: int
    source: str


class RawTiledMap(TypedDict):
    """The keys and their types that appear in a Tiled JSON Map Object.

    Tiled Docs: https://doc.mapeditor.org/en/stable/reference/json-map-format/#map
    """

    backgroundcolor: str
    compressionlevel: int
    height: int
    hexsidelength: int
    infinite: bool
    layers: List[RawLayer]
    nextlayerid: int
    nextobjectid: int
    orientation: str
    properties: List[RawProperty]
    renderorder: str
    staggeraxis: str
    staggerindex: str
    tiledversion: str
    tileheight: int
    tilesets: List[RawTilesetMapping]
    tilewidth: int
    type: str
    version: Union[str, float]
    width: int


def parse(file: Path) -> TiledMap:
    """Parse the raw Tiled map into a pytiled_parser type.

    Args:
        file: Path to the map file.

    Returns:
        TiledMap: A parsed TiledMap.
    """
    with open(file) as map_file:
        raw_tiled_map = json.load(map_file)

    parent_dir = file.parent

    raw_tilesets: List[Union[RawTileSet, RawTilesetMapping]] = raw_tiled_map["tilesets"]
    tilesets: TilesetDict = {}

    for raw_tileset in raw_tilesets:
        if raw_tileset.get("source") is not None:
            # Is an external Tileset
            tileset_path = Path(parent_dir / raw_tileset["source"])
            parser = check_format(tileset_path)
            with open(tileset_path) as raw_tileset_file:
                if parser == "json":
                    tilesets[raw_tileset["firstgid"]] = parse_json_tileset(
                        json.load(raw_tileset_file),
                        raw_tileset["firstgid"],
                        external_path=tileset_path.parent,
                    )
                elif parser == "tmx":
                    raw_tileset_external = etree.parse(raw_tileset_file).getroot()
                    tilesets[raw_tileset["firstgid"]] = parse_tmx_tileset(
                        raw_tileset_external,
                        raw_tileset["firstgid"],
                        external_path=tileset_path.parent,
                    )
                else:
                    raise UnknownFormat(
                        "Unkown Tileset format, please use either the TSX or JSON format."
                    )

        else:
            # Is an embedded Tileset
            raw_tileset = cast(RawTileSet, raw_tileset)
            tilesets[raw_tileset["firstgid"]] = parse_json_tileset(
                raw_tileset, raw_tileset["firstgid"]
            )

    if isinstance(raw_tiled_map["version"], float):
        version = str(raw_tiled_map["version"])
    else:
        version = raw_tiled_map["version"]

    # `map` is a built-in function
    map_ = TiledMap(
        map_file=file,
        infinite=raw_tiled_map["infinite"],
        layers=[parse_layer(layer_, parent_dir) for layer_ in raw_tiled_map["layers"]],
        map_size=Size(raw_tiled_map["width"], raw_tiled_map["height"]),
        next_layer_id=raw_tiled_map["nextlayerid"],
        next_object_id=raw_tiled_map["nextobjectid"],
        orientation=raw_tiled_map["orientation"],
        render_order=raw_tiled_map["renderorder"],
        tiled_version=raw_tiled_map["tiledversion"],
        tile_size=Size(raw_tiled_map["tilewidth"], raw_tiled_map["tileheight"]),
        tilesets=tilesets,
        version=version,
    )

    layers = [layer for layer in map_.layers if hasattr(layer, "tiled_objects")]

    for my_layer in layers:
        for tiled_object in my_layer.tiled_objects:  # type: ignore
            if hasattr(tiled_object, "new_tileset"):
                if tiled_object.new_tileset:
                    already_loaded = None
                    for val in map_.tilesets.values():
                        if val.name == tiled_object.new_tileset["name"]:
                            already_loaded = val
                            break

                    if not already_loaded:
                        highest_firstgid = max(map_.tilesets.keys())
                        last_tileset_count = map_.tilesets[highest_firstgid].tile_count
                        new_firstgid = highest_firstgid + last_tileset_count
                        map_.tilesets[new_firstgid] = parse_json_tileset(
                            tiled_object.new_tileset,
                            new_firstgid,
                            tiled_object.new_tileset_path,
                        )
                        tiled_object.gid = tiled_object.gid + (new_firstgid - 1)

                    else:
                        tiled_object.gid = tiled_object.gid + (
                            already_loaded.firstgid - 1
                        )

                    tiled_object.new_tileset = None
                    tiled_object.new_tileset_path = None

    if raw_tiled_map.get("backgroundcolor") is not None:
        map_.background_color = parse_color(raw_tiled_map["backgroundcolor"])

    if raw_tiled_map.get("hexsidelength") is not None:
        map_.hex_side_length = raw_tiled_map["hexsidelength"]

    if raw_tiled_map.get("properties") is not None:
        map_.properties = parse_properties(raw_tiled_map["properties"])

    if raw_tiled_map.get("staggeraxis") is not None:
        map_.stagger_axis = raw_tiled_map["staggeraxis"]

    if raw_tiled_map.get("staggerindex") is not None:
        map_.stagger_index = raw_tiled_map["staggerindex"]

    return map_
