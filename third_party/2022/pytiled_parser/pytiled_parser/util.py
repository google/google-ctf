"""Utility Functions for PyTiled"""
import json
import xml.etree.ElementTree as etree
from pathlib import Path
from typing import Any

from pytiled_parser.common_types import Color


def parse_color(color: str) -> Color:
    """Convert Tiled color format into PyTiled's.
    Args:
        color (str): Tiled formatted color string.
    Returns:
        :Color: Color object in the format that PyTiled understands.
    """
    # the actual part we care about is always an even number
    if len(color) % 2:
        # strip initial '#' character
        color = color[1:]

    if len(color) == 6:
        # full opacity if no alpha specified
        return Color(int(color[0:2], 16), int(color[2:4], 16), int(color[4:6], 16), 255)
    elif len(color) == 8:
        return Color(
            int(color[2:4], 16),
            int(color[4:6], 16),
            int(color[6:8], 16),
            int(color[0:2], 16),
        )

    raise ValueError("Improperly formatted color passed to parse_color")


def check_format(file_path: Path) -> str:
    with open(file_path) as file:
        line = file.readline().rstrip().strip()
        if line[0] == "<":
            return "tmx"
        else:
            return "json"


def load_object_template(file_path: Path) -> Any:
    template_format = check_format(file_path)

    new_tileset = None
    new_tileset_path = None

    if template_format == "tmx":
        with open(file_path) as template_file:
            template = etree.parse(template_file).getroot()

            tileset_element = template.find("./tileset")
            if tileset_element is not None:
                tileset_path = Path(file_path.parent / tileset_element.attrib["source"])
                new_tileset = load_object_tileset(tileset_path)
                new_tileset_path = tileset_path.parent
    elif template_format == "json":
        with open(file_path) as template_file:
            template = json.load(template_file)
            if "tileset" in template:
                tileset_path = Path(file_path.parent / template["tileset"]["source"])  # type: ignore
                new_tileset = load_object_tileset(tileset_path)
                new_tileset_path = tileset_path.parent

    return (template, new_tileset, new_tileset_path)


def load_object_tileset(file_path: Path) -> Any:
    tileset_format = check_format(file_path)

    new_tileset = None

    with open(file_path) as tileset_file:
        if tileset_format == "tmx":
            new_tileset = etree.parse(tileset_file).getroot()
        elif tileset_format == "json":
            new_tileset = json.load(tileset_file)

    return new_tileset
