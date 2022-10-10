"""Tests for maps"""
import importlib.util
import os
from pathlib import Path

import pytest

from pytiled_parser import parse_map
from pytiled_parser.common_types import OrderedPair, Size

TESTS_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
TEST_DATA = TESTS_DIR / "test_data"
MAP_TESTS = TEST_DATA / "map_tests"

ALL_MAP_TESTS = [
    MAP_TESTS / "external_tileset_dif_dir",
    MAP_TESTS / "no_layers",
    MAP_TESTS / "no_background_color",
    MAP_TESTS / "hexagonal",
    MAP_TESTS / "embedded_tileset",
    MAP_TESTS / "template",
]


def fix_object(my_object):
    my_object.coordinates = OrderedPair(
        round(my_object.coordinates[0], 3), round(my_object.coordinates[1], 3)
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


def fix_layer(layer):
    for tiled_object in layer.tiled_objects:
        fix_object(tiled_object)


def fix_map(map):
    map.version = None
    map.tiled_version = None
    for layer in [layer for layer in map.layers if hasattr(layer, "tiled_objects")]:
        fix_layer(layer)

    for tileset in map.tilesets.values():
        fix_tileset(tileset)


@pytest.mark.parametrize("parser_type", ["json", "tmx"])
@pytest.mark.parametrize("map_test", ALL_MAP_TESTS)
def test_map_integration(parser_type, map_test):
    # it's a PITA to import like this, don't do it
    # https://stackoverflow.com/a/67692/1342874
    spec = importlib.util.spec_from_file_location("expected", map_test / "expected.py")
    expected = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(expected)

    if parser_type == "json":
        raw_maps_path = map_test / "map.json"
    elif parser_type == "tmx":
        raw_maps_path = map_test / "map.tmx"

    casted_map = parse_map(raw_maps_path)

    # file detection when running from unit tests is broken
    expected.EXPECTED.map_file = casted_map.map_file

    # who even knows what/how/when the gods determine what the
    # version values in maps/tileset files are, so we're just not
    # gonna check them, because they don't make sense anyways.
    #
    # Yes the values could be set to None in the expected objects
    # directly, but alas, this is just test code that's already stupid fast
    # and I'm lazy because there's too many of them already existing.
    fix_map(expected.EXPECTED)
    fix_map(casted_map)
    assert casted_map == expected.EXPECTED
