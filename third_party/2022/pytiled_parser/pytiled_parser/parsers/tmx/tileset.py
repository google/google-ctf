import xml.etree.ElementTree as etree
from pathlib import Path
from typing import Optional

from pytiled_parser.common_types import OrderedPair
from pytiled_parser.parsers.tmx.layer import parse as parse_layer
from pytiled_parser.parsers.tmx.properties import parse as parse_properties
from pytiled_parser.parsers.tmx.wang_set import parse as parse_wangset
from pytiled_parser.tileset import Frame, Grid, Tile, Tileset, Transformations
from pytiled_parser.util import parse_color


def _parse_frame(raw_frame: etree.Element) -> Frame:
    """Parse the raw_frame to a Frame object.

    Args:
        raw_frame: XML Element to be parsed to a Frame

    Returns:
        Frame: The Frame created from the raw_frame
    """

    return Frame(
        duration=int(raw_frame.attrib["duration"]),
        tile_id=int(raw_frame.attrib["tileid"]),
    )


def _parse_grid(raw_grid: etree.Element) -> Grid:
    """Parse the raw_grid to a Grid object.

    Args:
        raw_grid: XML Element to be parsed to a Grid

    Returns:
        Grid: The Grid created from the raw_grid
    """

    return Grid(
        orientation=raw_grid.attrib["orientation"],
        width=int(raw_grid.attrib["width"]),
        height=int(raw_grid.attrib["height"]),
    )


def _parse_transformations(raw_transformations: etree.Element) -> Transformations:
    """Parse the raw_transformations to a Transformations object.

    Args:
        raw_transformations: XML Element to be parsed to a Transformations

    Returns:
        Transformations: The Transformations created from the raw_transformations
    """

    return Transformations(
        hflip=bool(int(raw_transformations.attrib["hflip"])),
        vflip=bool(int(raw_transformations.attrib["vflip"])),
        rotate=bool(int(raw_transformations.attrib["rotate"])),
        prefer_untransformed=bool(
            int(raw_transformations.attrib["preferuntransformed"])
        ),
    )


def _parse_tile(raw_tile: etree.Element, external_path: Optional[Path] = None) -> Tile:
    """Parse the raw_tile to a Tile object.

    Args:
        raw_tile: XML Element to be parsed to a Tile

    Returns:
        Tile: The Tile created from the raw_tile
    """

    tile = Tile(id=int(raw_tile.attrib["id"]))

    if raw_tile.attrib.get("type") is not None:
        tile.type = raw_tile.attrib["type"]

    animation_element = raw_tile.find("./animation")
    if animation_element is not None:
        tile.animation = []
        for raw_frame in animation_element.findall("./frame"):
            tile.animation.append(_parse_frame(raw_frame))

    object_element = raw_tile.find("./objectgroup")
    if object_element is not None:
        tile.objects = parse_layer(object_element)

    properties_element = raw_tile.find("./properties")
    if properties_element is not None:
        tile.properties = parse_properties(properties_element)

    image_element = raw_tile.find("./image")
    if image_element is not None:
        if external_path:
            tile.image = (
                Path(external_path / image_element.attrib["source"])
                .absolute()
                .resolve()
            )
        else:
            tile.image = Path(image_element.attrib["source"])

        tile.image_width = int(image_element.attrib["width"])
        tile.image_height = int(image_element.attrib["height"])

    return tile


def parse(
    raw_tileset: etree.Element,
    firstgid: int,
    external_path: Optional[Path] = None,
) -> Tileset:
    tileset = Tileset(
        name=raw_tileset.attrib["name"],
        tile_count=int(raw_tileset.attrib["tilecount"]),
        tile_width=int(raw_tileset.attrib["tilewidth"]),
        tile_height=int(raw_tileset.attrib["tileheight"]),
        columns=int(raw_tileset.attrib["columns"]),
        firstgid=firstgid,
        alignment=raw_tileset.attrib.get("objectalignment", "bottomleft"),
    )

    if raw_tileset.attrib.get("version") is not None:
        tileset.version = raw_tileset.attrib["version"]

    if raw_tileset.attrib.get("tiledversion") is not None:
        tileset.tiled_version = raw_tileset.attrib["tiledversion"]

    if raw_tileset.attrib.get("backgroundcolor") is not None:
        tileset.background_color = parse_color(raw_tileset.attrib["backgroundcolor"])

    if raw_tileset.attrib.get("spacing") is not None:
        tileset.spacing = int(raw_tileset.attrib["spacing"])

    if raw_tileset.attrib.get("margin") is not None:
        tileset.margin = int(raw_tileset.attrib["margin"])

    image_element = raw_tileset.find("image")
    if image_element is not None:
        if external_path:
            tileset.image = (
                Path(external_path / image_element.attrib["source"])
                .absolute()
                .resolve()
            )
        else:
            tileset.image = Path(image_element.attrib["source"])

        tileset.image_width = int(image_element.attrib["width"])
        tileset.image_height = int(image_element.attrib["height"])

        if image_element.attrib.get("trans") is not None:
            my_string = image_element.attrib["trans"]
            if my_string[0] != "#":
                my_string = f"#{my_string}"
            tileset.transparent_color = parse_color(my_string)

    tileoffset_element = raw_tileset.find("./tileoffset")
    if tileoffset_element is not None:
        tileset.tile_offset = OrderedPair(
            int(tileoffset_element.attrib["x"]), int(tileoffset_element.attrib["y"])
        )

    grid_element = raw_tileset.find("./grid")
    if grid_element is not None:
        tileset.grid = _parse_grid(grid_element)

    properties_element = raw_tileset.find("./properties")
    if properties_element is not None:
        tileset.properties = parse_properties(properties_element)

    tiles = {}
    for tile_element in raw_tileset.findall("./tile"):
        tiles[int(tile_element.attrib["id"])] = _parse_tile(
            tile_element, external_path=external_path
        )
    if tiles:
        tileset.tiles = tiles

    wangsets_element = raw_tileset.find("./wangsets")
    if wangsets_element is not None:
        wangsets = []
        for raw_wangset in wangsets_element.findall("./wangset"):
            wangsets.append(parse_wangset(raw_wangset))
        tileset.wang_sets = wangsets

    transformations_element = raw_tileset.find("./transformations")
    if transformations_element is not None:
        tileset.transformations = _parse_transformations(transformations_element)

    return tileset
