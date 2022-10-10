import xml.etree.ElementTree as etree

from pytiled_parser.parsers.tmx.properties import parse as parse_properties
from pytiled_parser.util import parse_color
from pytiled_parser.wang_set import WangColor, WangSet, WangTile


def _parse_wang_tile(raw_wang_tile: etree.Element) -> WangTile:
    """Parse the raw wang tile into a pytiled_parser type

    Args:
        raw_wang_tile: XML Element to be parsed.

    Returns:
        WangTile: A properly typed WangTile.
    """
    ids = [int(v.strip()) for v in raw_wang_tile.attrib["wangid"].split(",")]
    return WangTile(tile_id=int(raw_wang_tile.attrib["tileid"]), wang_id=ids)


def _parse_wang_color(raw_wang_color: etree.Element) -> WangColor:
    """Parse the raw wang color into a pytiled_parser type

    Args:
        raw_wang_color: XML Element to be parsed.

    Returns:
        WangColor: A properly typed WangColor.
    """
    wang_color = WangColor(
        name=raw_wang_color.attrib["name"],
        color=parse_color(raw_wang_color.attrib["color"]),
        tile=int(raw_wang_color.attrib["tile"]),
        probability=float(raw_wang_color.attrib["probability"]),
    )

    properties = raw_wang_color.find("./properties")
    if properties:
        wang_color.properties = parse_properties(properties)

    return wang_color


def parse(raw_wangset: etree.Element) -> WangSet:
    """Parse the raw wangset into a pytiled_parser type

    Args:
        raw_wangset: XML Element to be parsed.

    Returns:
        WangSet: A properly typed WangSet.
    """

    colors = []
    for raw_wang_color in raw_wangset.findall("./wangcolor"):
        colors.append(_parse_wang_color(raw_wang_color))

    tiles = {}
    for raw_wang_tile in raw_wangset.findall("./wangtile"):
        tiles[int(raw_wang_tile.attrib["tileid"])] = _parse_wang_tile(raw_wang_tile)

    wangset = WangSet(
        name=raw_wangset.attrib["name"],
        tile=int(raw_wangset.attrib["tile"]),
        wang_type=raw_wangset.attrib["type"],
        wang_colors=colors,
        wang_tiles=tiles,
    )

    properties = raw_wangset.find("./properties")
    if properties:
        wangset.properties = parse_properties(properties)

    return wangset
