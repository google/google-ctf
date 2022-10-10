import json
import re
from os import listdir
from os.path import isfile, join
from pathlib import Path
from typing import List

import attr
from typing_extensions import TypedDict

from pytiled_parser.common_types import OrderedPair, Size
from pytiled_parser.parser import parse_map
from pytiled_parser.tiled_map import TiledMap


@attr.s(auto_attribs=True)
class WorldMap:

    tiled_map: TiledMap
    size: Size
    coordinates: OrderedPair


@attr.s(auto_attribs=True)
class World:

    maps: List[WorldMap]
    only_show_adjacent: bool = False


class RawPattern(TypedDict):
    """The keys and their types that appear in a Pattern JSON Object."""

    regexp: str
    multiplierX: float
    multiplierY: float
    offsetX: float
    offsetY: float


class RawWorldMap(TypedDict):
    """The keys and their types that appear in a WorldMap JSON Object."""

    fileName: str
    height: float
    width: float
    x: float
    y: float


class RawWorld(TypedDict):
    """The keys and their types that appear in a World JSON Object."""

    maps: List[RawWorldMap]
    patterns: List[RawPattern]
    onlyShowAdjacentMaps: bool


def _parse_world_map(raw_world_map: RawWorldMap, map_file: Path) -> WorldMap:
    """Parse the RawWorldMap into a WorldMap.

    Args:
        raw_world_map: The RawWorldMap to parse
        map_file: The file of tiled_map to parse

    Returns:
        WorldMap: The parsed WorldMap object
    """
    tiled_map = parse_map(map_file)

    return WorldMap(
        tiled_map=tiled_map,
        size=Size(raw_world_map["width"], raw_world_map["height"]),
        coordinates=OrderedPair(raw_world_map["x"], raw_world_map["y"]),
    )


def parse_world(file: Path) -> World:
    """Parse the raw world into a pytiled_parser type

    Args:
        file: Path to the world's file

    Returns:
        World: A properly parsed World
    """

    with open(file) as world_file:
        raw_world = json.load(world_file)

    parent_dir = file.parent

    maps: List[WorldMap] = []

    if raw_world.get("maps"):
        for raw_map in raw_world["maps"]:
            map_path = Path(parent_dir / raw_map["fileName"])
            maps.append(_parse_world_map(raw_map, map_path))

    if raw_world.get("patterns"):
        for raw_pattern in raw_world["patterns"]:
            regex = re.compile(raw_pattern["regexp"])
            map_files = [
                f
                for f in listdir(parent_dir)
                if isfile(join(parent_dir, f)) and regex.match(f)
            ]
            for map_file in map_files:
                search = regex.search(map_file)
                if search:
                    width = raw_pattern["multiplierX"]
                    height = raw_pattern["multiplierY"]

                    offset_x = 0
                    offset_y = 0

                    if raw_pattern.get("offsetX"):
                        offset_x = raw_pattern["offsetX"]

                    if raw_pattern.get("offsetY"):
                        offset_y = raw_pattern["offsetY"]

                    x = (float(search.group(1)) * width) + offset_x
                    y = (float(search.group(2)) * height) + offset_y

                    raw_world_map: RawWorldMap = {
                        "fileName": map_file,
                        "width": width,
                        "height": height,
                        "x": x,
                        "y": y,
                    }

                    map_path = Path(parent_dir / map_file)
                    maps.append(_parse_world_map(raw_world_map, map_path))

    world = World(maps=maps)

    if raw_world.get("onlyShowAdjacentMaps"):
        world.only_show_adjacent = raw_world["onlyShowAdjacentMaps"]

    return world
