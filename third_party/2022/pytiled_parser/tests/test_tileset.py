"""Tests for tilesets"""
import importlib.util
import json
import os
import xml.etree.ElementTree as etree
from pathlib import Path

import pytest

from pytiled_parser.common_types import OrderedPair, Size
from pytiled_parser.parsers.json.tileset import parse as parse_json
from pytiled_parser.parsers.tmx.tileset import parse as parse_tmx

TESTS_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
TEST_DATA = TESTS_DIR / "test_data"
TILE_SETS = TEST_DATA / "tilesets"


ALL_TILESET_DIRS = [
    TILE_SETS / "image",
    TILE_SETS / "image_background_color",
    TILE_SETS / "image_grid",
    TILE_SETS / "image_properties",
    TILE_SETS / "image_transparent_color",
    TILE_SETS / "image_tile_offset",
    TILE_SETS / "image_transformations",
    TILE_SETS / "individual_images",
    TILE_SETS / "terrain",
]


def fix_object(my_object):
    my_object.coordinates = OrderedPair(
        round(my_object.coordinates[0], 4), round(my_object.coordinates[1], 4)
    )
    my_object.size = Size(round(my_object.size[0], 4), round(my_object.size[1], 4))


def fix_tileset(tileset):
    tileset.version = None
    tileset.tiled_version = None
    if tileset.tiles:
        for tile in tileset.tiles.values():
            if tile.objects:
                for my_object in tile.objects.tiled_objects:
                    fix_object(my_object)


@pytest.mark.parametrize("parser_type", ["json", "tmx"])
@pytest.mark.parametrize("tileset_dir", ALL_TILESET_DIRS)
def test_tilesets_integration(parser_type, tileset_dir):
    # it's a PITA to import like this, don't do it
    # https://stackoverflow.com/a/67692/1342874
    spec = importlib.util.spec_from_file_location(
        "expected", tileset_dir / "expected.py"
    )
    expected = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(expected)

    if parser_type == "json":
        raw_tileset_path = tileset_dir / "tileset.json"
        with open(raw_tileset_path) as raw_tileset:
            tileset_ = parse_json(json.loads(raw_tileset.read()), 1)
    elif parser_type == "tmx":
        raw_tileset_path = tileset_dir / "tileset.tsx"
        with open(raw_tileset_path) as raw_tileset:
            tileset_ = parse_tmx(etree.parse(raw_tileset).getroot(), 1)

    fix_tileset(tileset_)
    fix_tileset(expected.EXPECTED)

    assert tileset_ == expected.EXPECTED
