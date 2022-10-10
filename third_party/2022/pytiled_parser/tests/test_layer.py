"""Tests for tilesets"""
import importlib.util
import json
import os
import xml.etree.ElementTree as etree
from pathlib import Path

import pytest

from pytiled_parser.common_types import OrderedPair, Size
from pytiled_parser.parsers.json.layer import parse as parse_json
from pytiled_parser.parsers.tmx.layer import parse as parse_tmx

TESTS_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
TEST_DATA = TESTS_DIR / "test_data"
LAYER_TESTS = TEST_DATA / "layer_tests"


ALL_LAYER_TESTS = [
    LAYER_TESTS / "all_layer_types",
    LAYER_TESTS / "b64",
    LAYER_TESTS / "b64_gzip",
    LAYER_TESTS / "b64_zlib",
    # LAYER_TESTS / "b64_zstd",
    LAYER_TESTS / "no_layers",
    LAYER_TESTS / "infinite_map",
    LAYER_TESTS / "infinite_map_b64",
]


def fix_object(my_object):
    my_object.coordinates = OrderedPair(
        round(my_object.coordinates[0], 4),
        round(my_object.coordinates[1], 4),
    )
    my_object.size = Size(round(my_object.size[0], 4), round(my_object.size[1], 4))


def fix_layer(layer):
    layer.offset = OrderedPair(round(layer.offset[0], 3), round(layer.offset[1], 3))
    layer.coordinates = OrderedPair(
        round(layer.coordinates[0], 4), round(layer.coordinates[1], 4)
    )
    if layer.size:
        layer.size = Size(round(layer.size[0], 4), round(layer.size[1], 4))
    layer.parallax_factor = OrderedPair(
        round(layer.parallax_factor[0], 4),
        round(layer.parallax_factor[1], 4),
    )
    if hasattr(layer, "tiled_objects"):
        for tiled_object in layer.tiled_objects:
            fix_object(tiled_object)
    if hasattr(layer, "layers"):
        for child_layer in layer.layers:
            fix_layer(child_layer)


@pytest.mark.parametrize("parser_type", ["json", "tmx"])
@pytest.mark.parametrize("layer_test", ALL_LAYER_TESTS)
def test_layer_integration(parser_type, layer_test):
    # it's a PITA to import like this, don't do it
    # https://stackoverflow.com/a/67692/1342874
    spec = importlib.util.spec_from_file_location(
        "expected", layer_test / "expected.py"
    )
    expected = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(expected)

    if parser_type == "json":
        raw_layers_path = layer_test / "map.json"
        with open(raw_layers_path) as raw_layers_file:
            raw_layers = json.load(raw_layers_file)["layers"]
            layers = [parse_json(raw_layer) for raw_layer in raw_layers]
    elif parser_type == "tmx":
        raw_layers_path = layer_test / "map.tmx"
        with open(raw_layers_path) as raw_layers_file:
            raw_layer = etree.parse(raw_layers_file).getroot()
            layers = []
            for layer in raw_layer.findall("./layer"):
                layers.append(parse_tmx(layer))

            for layer in raw_layer.findall("./objectgroup"):
                layers.append(parse_tmx(layer))

            for layer in raw_layer.findall("./group"):
                layers.append(parse_tmx(layer))

            for layer in raw_layer.findall("./imagelayer"):
                layers.append(parse_tmx(layer))

    for layer in layers:
        fix_layer(layer)

    for layer in expected.EXPECTED:
        fix_layer(layer)
        print(layer.size)

    assert layers == expected.EXPECTED
