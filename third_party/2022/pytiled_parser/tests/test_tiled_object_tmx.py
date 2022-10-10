"""Tests for objects"""
import xml.etree.ElementTree as etree
from contextlib import ExitStack as does_not_raise
from pathlib import Path

import pytest

from pytiled_parser import common_types
from pytiled_parser.parsers.tmx.tiled_object import parse
from pytiled_parser.tiled_object import (
    Ellipse,
    Point,
    Polygon,
    Polyline,
    Rectangle,
    Text,
    Tile,
)

ELLIPSES = [
    (
        """
        <object id="6" x="37.5401" y="81.1913" width="57.4014" height="18.5518" name="ellipse">
         <ellipse/>
        </object>
        """,
        Ellipse(
            id=6,
            size=common_types.Size(57.4014, 18.5518),
            name="ellipse",
            coordinates=common_types.OrderedPair(37.5401, 81.1913),
        ),
    ),
    (
        """
        <object id="7" x="22.6986" y="53.9093" width="6.3294" height="31.4289" name="ellipse - invisible" visible="0">
         <ellipse/>
        </object>
        """,
        Ellipse(
            id=7,
            size=common_types.Size(6.3294, 31.4289),
            name="ellipse - invisible",
            visible=False,
            coordinates=common_types.OrderedPair(22.6986, 53.9093),
        ),
    ),
    (
        """
        <object id="8" x="35.7940" y="120.0409" width="29.6828" height="24.2264" name="ellipse - rotated" rotation="111">
         <ellipse/>
        </object>
        """,
        Ellipse(
            id=8,
            size=common_types.Size(29.6828, 24.2264),
            name="ellipse - rotated",
            rotation=111,
            coordinates=common_types.OrderedPair(35.7940, 120.0409),
        ),
    ),
    (
        """
        <object id="29" x="72.4611" y="127.6799" name="ellipse - no width or height">
         <ellipse/>
        </object>
        """,
        Ellipse(
            id=29,
            name="ellipse - no width or height",
            coordinates=common_types.OrderedPair(72.4611, 127.6799),
        ),
    ),
]

RECTANGLES = [
    (
        """
        <object id="1" x="27.7185" y="23.5717" width="45.3973" height="41.4687" name="rectangle"/>
        """,
        Rectangle(
            id=1,
            size=common_types.Size(45.3973, 41.4687),
            coordinates=common_types.OrderedPair(27.7185, 23.5717),
            name="rectangle",
        ),
    ),
    (
        """
        <object id="4" x="163.9104" y="91.0128" width="30.9924" height="32.7384" name="rectangle - invisible" visible="0"/>
        """,
        Rectangle(
            id=4,
            size=common_types.Size(30.9924, 32.7384),
            coordinates=common_types.OrderedPair(163.9104, 91.0128),
            name="rectangle - invisible",
            visible=False,
        ),
    ),
    (
        """
        <object id="5" x="183.3352" y="23.3534" width="10" height="22" name="rectangle - rotated" rotation="10"/>
        """,
        Rectangle(
            id=5,
            size=common_types.Size(10, 22),
            coordinates=common_types.OrderedPair(183.3352, 23.3534),
            name="rectangle - rotated",
            rotation=10,
        ),
    ),
    (
        """
        <object id="28" x="131.1720" y="53.4728" name="rectangle - no width or height"/>
        """,
        Rectangle(
            id=28,
            coordinates=common_types.OrderedPair(131.1720, 53.4728),
            name="rectangle - no width or height",
        ),
    ),
    (
        r"""
        <object id="30" x="39.0679" y="131.8268" width="21.1709" height="13.7501" name="rectangle - properties">
         <properties>
          <property name="bool property" type="bool" value="false"/>
          <property name="color property" type="color" value="#ffaa0000"/>
          <property name="file property" type="file" value="..\/..\/..\/..\/..\/..\/dev\/null"/>
          <property name="float property" type="float" value="42.1"/>
          <property name="int property" type="int" value="8675309"/>
          <property name="string property" value="pytiled_parser rulez!1!!"/>
         </properties>
        </object>
        """,
        Rectangle(
            id=30,
            size=common_types.Size(21.1709, 13.7501),
            coordinates=common_types.OrderedPair(39.0679, 131.8268),
            name="rectangle - properties",
            properties={
                "bool property": False,
                "color property": common_types.Color(170, 0, 0, 255),
                "file property": Path("../../../../../../dev/null"),
                "float property": 42.1,
                "int property": 8675309,
                "string property": "pytiled_parser rulez!1!!",
            },
        ),
    ),
]

POINTS = [
    (
        """
        <object id="2" x="159.9818" y="82.9374" name="point">
         <point/>
        </object>
        """,
        Point(
            id=2, coordinates=common_types.OrderedPair(159.9818, 82.9374), name="point"
        ),
    ),
    (
        """
        <object id="2" x="159.9818" y="82.9374" name="point - invisible" visible="0">
         <point/>
        </object>
        """,
        Point(
            id=2,
            coordinates=common_types.OrderedPair(159.9818, 82.9374),
            name="point - invisible",
            visible=False,
        ),
    ),
]

POLYGONS = [
    (
        """
        <object id="9" x="89.4851" y="38.6314" name="polygon">
         <polygon points="0,0 19.4248,27.0638 19.6431,3.0556 -2.6191,15.9327 25.3177,16.3692"/>
        </object>
        """,
        Polygon(
            id=9,
            coordinates=common_types.OrderedPair(89.4851, 38.6314),
            name="polygon",
            points=[
                common_types.OrderedPair(0, 0),
                common_types.OrderedPair(19.4248, 27.0638),
                common_types.OrderedPair(19.6431, 3.0556),
                common_types.OrderedPair(-2.6191, 15.9327),
                common_types.OrderedPair(25.3177, 16.3692),
            ],
        ),
    ),
    (
        """
        <object id="9" x="89.4851" y="38.6314" name="polygon - invisible" visible="0">
         <polygon points="0,0 19.4248,27.0638 19.6431,3.0556 -2.6191,15.9327 25.3177,16.3692"/>
        </object>
        """,
        Polygon(
            id=9,
            coordinates=common_types.OrderedPair(89.4851, 38.6314),
            name="polygon - invisible",
            points=[
                common_types.OrderedPair(0, 0),
                common_types.OrderedPair(19.4248, 27.0638),
                common_types.OrderedPair(19.6431, 3.0556),
                common_types.OrderedPair(-2.6191, 15.9327),
                common_types.OrderedPair(25.3177, 16.3692),
            ],
            visible=False,
        ),
    ),
    (
        """
        <object id="9" x="89.4851" y="38.6314" name="polygon - rotated" rotation="123">
         <polygon points="0,0 19.4248,27.0638 19.6431,3.0556 -2.6191,15.9327 25.3177,16.3692"/>
        </object>
        """,
        Polygon(
            id=9,
            coordinates=common_types.OrderedPair(89.4851, 38.6314),
            name="polygon - rotated",
            points=[
                common_types.OrderedPair(0, 0),
                common_types.OrderedPair(19.4248, 27.0638),
                common_types.OrderedPair(19.6431, 3.0556),
                common_types.OrderedPair(-2.6191, 15.9327),
                common_types.OrderedPair(25.3177, 16.3692),
            ],
            rotation=123,
        ),
    ),
]

POLYLINES = [
    (
        """
        <object id="12" x="124.1878" y="90.1398" name="polyline">
         <polyline points="0,0 -13.3136,41.0321 21.3891,16.8057"/>
        </object>
        """,
        Polyline(
            id=12,
            coordinates=common_types.OrderedPair(124.1878, 90.1398),
            name="polyline",
            points=[
                common_types.OrderedPair(0, 0),
                common_types.OrderedPair(-13.3136, 41.0321),
                common_types.OrderedPair(21.3891, 16.8057),
            ],
        ),
    ),
    (
        """
        <object id="12" x="124.1878" y="90.1398" name="polyline - invisible" visible="0">
         <polyline points="0,0 -13.3136,41.0321 21.3891,16.8057"/>
        </object>
        """,
        Polyline(
            id=12,
            coordinates=common_types.OrderedPair(124.1878, 90.1398),
            name="polyline - invisible",
            points=[
                common_types.OrderedPair(0, 0),
                common_types.OrderedPair(-13.3136, 41.0321),
                common_types.OrderedPair(21.3891, 16.8057),
            ],
            visible=False,
        ),
    ),
    (
        """
        <object id="12" x="124.1878" y="90.1398" name="polyline - rotated" rotation="110">
         <polyline points="0,0 -13.3136,41.0321 21.3891,16.8057"/>
        </object>
        """,
        Polyline(
            id=12,
            coordinates=common_types.OrderedPair(124.1878, 90.1398),
            name="polyline - rotated",
            points=[
                common_types.OrderedPair(0, 0),
                common_types.OrderedPair(-13.3136, 41.0321),
                common_types.OrderedPair(21.3891, 16.8057),
            ],
            rotation=110,
        ),
    ),
]

TEXTS = [
    (
        """
        <object id="19" x="93.2987" y="81.7106" name="text" width="92.375" height="19">
         <text>Hello World</text>
        </object>
        """,
        Text(
            id=19,
            name="text",
            text="Hello World",
            size=common_types.Size(92.375, 19),
            coordinates=common_types.OrderedPair(93.2987, 81.7106),
        ),
    ),
    (
        """
        <object id="19" x="93.2987" y="81.7106" name="text - wrap" width="92.375" height="19">
         <text wrap="1">Hello World</text>
        </object>
        """,
        Text(
            id=19,
            name="text - wrap",
            text="Hello World",
            wrap=True,
            size=common_types.Size(92.375, 19),
            coordinates=common_types.OrderedPair(93.2987, 81.7106),
        ),
    ),
    (
        """
        <object id="19" x="93.2987" y="81.7106" name="text - rotated" width="92.375" height="19" rotation="110">
         <text>Hello World</text>
        </object>
        """,
        Text(
            id=19,
            name="text - rotated",
            text="Hello World",
            rotation=110,
            size=common_types.Size(92.375, 19),
            coordinates=common_types.OrderedPair(93.2987, 81.7106),
        ),
    ),
    (
        """
        <object id="19" x="93.2987" y="81.7106" name="text - different font" width="92.375" height="19" rotation="110">
         <text fontfamily="DejaVu Sans" pixelsize="19">Hello World</text>
        </object>
        """,
        Text(
            id=19,
            name="text - different font",
            text="Hello World",
            font_size=19,
            font_family="DejaVu Sans",
            rotation=110,
            size=common_types.Size(92.375, 19),
            coordinates=common_types.OrderedPair(93.2987, 81.7106),
        ),
    ),
    (
        """
        <object id="19" x="93.2987" y="81.7106" name="text - right bottom align" width="92.375" height="19">
         <text halign="right" valign="bottom">Hello World</text>
        </object>
        """,
        Text(
            id=19,
            name="text - right bottom align",
            text="Hello World",
            horizontal_align="right",
            vertical_align="bottom",
            size=common_types.Size(92.375, 19),
            coordinates=common_types.OrderedPair(93.2987, 81.7106),
        ),
    ),
    (
        """
        <object id="19" x="93.2987" y="81.7106" name="text - center center align" width="92.375" height="19">
         <text halign="center" valign="center">Hello World</text>
        </object>
        """,
        Text(
            id=19,
            name="text - center center align",
            text="Hello World",
            horizontal_align="center",
            vertical_align="center",
            size=common_types.Size(92.375, 19),
            coordinates=common_types.OrderedPair(93.2987, 81.7106),
        ),
    ),
    (
        """
        <object id="19" x="93.2987" y="81.7106" name="text - justified" width="92.375" height="19">
         <text halign="justify">Hello World</text>
        </object>
        """,
        Text(
            id=19,
            name="text - justified",
            text="Hello World",
            horizontal_align="justify",
            size=common_types.Size(92.375, 19),
            coordinates=common_types.OrderedPair(93.2987, 81.7106),
        ),
    ),
    (
        """
        <object id="19" x="93.2987" y="81.7106" name="text - colored" width="92.375" height="19">
         <text color="#aa0000">Hello World</text>
        </object>
        """,
        Text(
            id=19,
            name="text - colored",
            text="Hello World",
            color=common_types.Color(170, 0, 0, 255),
            size=common_types.Size(92.375, 19),
            coordinates=common_types.OrderedPair(93.2987, 81.7106),
        ),
    ),
    (
        """
        <object id="19" x="93.2987" y="81.7106" name="text - font options" width="92.375" height="19">
         <text bold="1" italic="1" kerning="1" strikeout="1" underline="1" wrap="1">Hello World</text>
        </object>
        """,
        Text(
            id=19,
            name="text - font options",
            text="Hello World",
            size=common_types.Size(92.375, 19),
            bold=True,
            italic=True,
            kerning=True,
            strike_out=True,
            underline=True,
            wrap=True,
            coordinates=common_types.OrderedPair(93.2987, 81.7106),
        ),
    ),
]

TILES = [
    (
        """
        <object id="13" x="111.8981" y="48.3019" width="32" height="32" name="tile" gid="79"/>
        """,
        Tile(
            id=13,
            size=common_types.Size(32, 32),
            name="tile",
            coordinates=common_types.OrderedPair(111.8981, 48.3019),
            gid=79,
        ),
    ),
    (
        """
        <object type="tile" id="13" x="111.8981" y="48.3019" width="32" height="32" name="tile - invisible" gid="79" visible="0"/>
        """,
        Tile(
            id=13,
            size=common_types.Size(32, 32),
            name="tile - invisible",
            type="tile",
            coordinates=common_types.OrderedPair(111.8981, 48.3019),
            gid=79,
            visible=False,
        ),
    ),
    (
        """
        <object id="13" x="111.8981" y="48.3019" width="32" height="32" name="tile - rotated" gid="79" rotation="110"/>
        """,
        Tile(
            id=13,
            size=common_types.Size(32, 32),
            name="tile - rotated",
            coordinates=common_types.OrderedPair(111.8981, 48.3019),
            gid=79,
            rotation=110,
        ),
    ),
]

OBJECTS = ELLIPSES + RECTANGLES + POINTS + POLYGONS + POLYLINES + TEXTS + TILES


@pytest.mark.parametrize("raw_object_tmx,expected", OBJECTS)
def test_parse_layer(raw_object_tmx, expected):
    raw_object = etree.fromstring(raw_object_tmx)
    result = parse(raw_object)

    assert result == expected
