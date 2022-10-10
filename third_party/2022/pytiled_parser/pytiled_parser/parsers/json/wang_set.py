from typing import List

from typing_extensions import TypedDict

from pytiled_parser.parsers.json.properties import RawProperty
from pytiled_parser.parsers.json.properties import parse as parse_properties
from pytiled_parser.util import parse_color
from pytiled_parser.wang_set import WangColor, WangSet, WangTile


class RawWangTile(TypedDict):
    """The keys and their types that appear in a Wang Tile JSON Object."""

    tileid: int
    # Tiled stores these IDs as a list represented like so:
    # [top, top_right, right, bottom_right, bottom, bottom_left, left, top_left]
    wangid: List[int]


class RawWangColor(TypedDict):
    """The keys and their types that appear in a Wang Color JSON Object."""

    color: str
    name: str
    probability: float
    tile: int
    properties: List[RawProperty]


class RawWangSet(TypedDict):
    """The keys and their types that appear in a Wang Set JSON Object."""

    colors: List[RawWangColor]
    name: str
    properties: List[RawProperty]
    tile: int
    type: str
    wangtiles: List[RawWangTile]


def _parse_wang_tile(raw_wang_tile: RawWangTile) -> WangTile:
    """Parse the raw wang tile into a pytiled_parser type

    Args:
        raw_wang_tile: RawWangTile to be parsed.

    Returns:
        WangTile: A properly typed WangTile.
    """
    return WangTile(tile_id=raw_wang_tile["tileid"], wang_id=raw_wang_tile["wangid"])


def _parse_wang_color(raw_wang_color: RawWangColor) -> WangColor:
    """Parse the raw wang color into a pytiled_parser type

    Args:
        raw_wang_color: RawWangColor to be parsed.

    Returns:
        WangColor: A properly typed WangColor.
    """
    wang_color = WangColor(
        name=raw_wang_color["name"],
        color=parse_color(raw_wang_color["color"]),
        tile=raw_wang_color["tile"],
        probability=raw_wang_color["probability"],
    )

    if raw_wang_color.get("properties") is not None:
        wang_color.properties = parse_properties(raw_wang_color["properties"])

    return wang_color


def parse(raw_wangset: RawWangSet) -> WangSet:
    """Parse the raw wangset into a pytiled_parser type

    Args:
        raw_wangset: Raw Wangset to be parsed.

    Returns:
        WangSet: A properly typed WangSet.
    """

    colors = []
    for raw_wang_color in raw_wangset["colors"]:
        colors.append(_parse_wang_color(raw_wang_color))

    tiles = {}
    for raw_wang_tile in raw_wangset["wangtiles"]:
        tiles[raw_wang_tile["tileid"]] = _parse_wang_tile(raw_wang_tile)

    wangset = WangSet(
        name=raw_wangset["name"],
        tile=raw_wangset["tile"],
        wang_type=raw_wangset["type"],
        wang_colors=colors,
        wang_tiles=tiles,
    )

    if raw_wangset.get("properties") is not None:
        wangset.properties = parse_properties(raw_wangset["properties"])

    return wangset
