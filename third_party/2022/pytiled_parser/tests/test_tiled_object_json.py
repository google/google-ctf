"""Tests for objects"""
import json
from contextlib import ExitStack as does_not_raise
from pathlib import Path

import pytest

from pytiled_parser import common_types
from pytiled_parser.parsers.json.tiled_object import parse
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
        {
        "ellipse":true,
        "height":18.5517790155735,
        "id":6,
        "name":"name: ellipse",
        "rotation":0,
        "type":"ellipse",
        "visible":true,
        "width":57.4013868364215,
        "x":37.5400704785722,
        "y":81.1913152210981
        }
        """,
        Ellipse(
            id=6,
            size=common_types.Size(57.4013868364215, 18.5517790155735),
            name="name: ellipse",
            rotation=0,
            type="ellipse",
            visible=True,
            coordinates=common_types.OrderedPair(37.5400704785722, 81.1913152210981),
        ),
    ),
    (
        """
        {
        "ellipse":true,
        "height":31.4288962146186,
        "id":7,
        "name":"name: ellipse - invisible",
        "rotation":0,
        "type":"ellipse",
        "visible":false,
        "width":6.32943048766625,
        "x":22.6986472661134,
        "y":53.9092872570194
        }
        """,
        Ellipse(
            id=7,
            size=common_types.Size(6.32943048766625, 31.4288962146186),
            name="name: ellipse - invisible",
            rotation=0,
            type="ellipse",
            visible=False,
            coordinates=common_types.OrderedPair(22.6986472661134, 53.9092872570194),
        ),
    ),
    (
        """
        {
        "ellipse":true,
        "height":24.2264408321018,
        "id":8,
        "name":"name: ellipse - rotated",
        "rotation":111,
        "type":"ellipse",
        "visible":true,
        "width":29.6828464249176,
        "x":35.7940206888712,
        "y":120.040923041946
        }
        """,
        Ellipse(
            id=8,
            size=common_types.Size(29.6828464249176, 24.2264408321018),
            name="name: ellipse - rotated",
            rotation=111,
            type="ellipse",
            visible=True,
            coordinates=common_types.OrderedPair(35.7940206888712, 120.040923041946),
        ),
    ),
    (
        """
        {
                 "ellipse":true,
                 "height":0,
                 "id":29,
                 "name":"name: ellipse - no width or height",
                 "rotation":0,
                 "type":"ellipse",
                 "visible":true,
                 "width":0,
                 "x":72.4610662725929,
                 "y":127.679890871888
        }
        """,
        Ellipse(
            id=29,
            name="name: ellipse - no width or height",
            rotation=0,
            type="ellipse",
            visible=True,
            coordinates=common_types.OrderedPair(72.4610662725929, 127.679890871888),
        ),
    ),
]

RECTANGLES = [
    (
        """
        {
        "height":41.4686825053996,
        "id":1,
        "name":"name: rectangle",
        "rotation":0,
        "type":"rectangle",
        "visible":true,
        "width":45.3972945322269,
        "x":27.7185404115039,
        "y":23.571672160964
        }
        """,
        Rectangle(
            id=1,
            size=common_types.Size(45.3972945322269, 41.4686825053996),
            name="name: rectangle",
            rotation=0,
            type="rectangle",
            visible=True,
            coordinates=common_types.OrderedPair(27.7185404115039, 23.571672160964),
        ),
    ),
    (
        """
        {
        "height":32.7384335568944,
        "id":4,
        "name":"name:  rectangle - invisible",
        "rotation":0,
        "type":"rectangle",
        "visible":false,
        "width":30.9923837671934,
        "x":163.910424008185,
        "y":91.0128452881664
        }
        """,
        Rectangle(
            id=4,
            size=common_types.Size(30.9923837671934, 32.7384335568944),
            name="name:  rectangle - invisible",
            rotation=0,
            type="rectangle",
            visible=False,
            coordinates=common_types.OrderedPair(163.910424008185, 91.0128452881664),
        ),
    ),
    (
        """
        {
        "height":22,
        "id":5,
        "name":"name:  rectangle - rotated",
        "rotation":10,
        "type":"rectangle",
        "visible":true,
        "width":10,
        "x":183.335227918609,
        "y":23.3534159372513
        }
        """,
        Rectangle(
            id=5,
            size=common_types.Size(10, 22),
            name="name:  rectangle - rotated",
            rotation=10,
            type="rectangle",
            visible=True,
            coordinates=common_types.OrderedPair(183.335227918609, 23.3534159372513),
        ),
    ),
    (
        """
        {
        "height":0,
        "id":28,
        "name":"name: rectangle - no width or height",
        "rotation":0,
        "type":"rectangle",
        "visible":true,
        "width":0,
        "x":131.17199045129,
        "y":53.4727748095942
        }
        """,
        Rectangle(
            id=28,
            size=common_types.Size(0, 0),
            name="name: rectangle - no width or height",
            rotation=0,
            type="rectangle",
            visible=True,
            coordinates=common_types.OrderedPair(131.17199045129, 53.4727748095942),
        ),
    ),
    (
        r"""
        {
         "height":13.7501420938956,
         "id":30,
         "name":"name: rectangle - properties",
         "properties":[
                {
                 "name":"bool property",
                 "type":"bool",
                 "value":false
                },
                {
                 "name":"color property",
                 "type":"color",
                 "value":"#ffaa0000"
                },
                {
                 "name":"file property",
                 "type":"file",
                 "value":"..\/..\/..\/..\/..\/..\/dev\/null"
                },
                {
                 "name":"float property",
                 "type":"float",
                 "value":42.1
                },
                {
                 "name":"int property",
                 "type":"int",
                 "value":8675309
                },
                {
                 "name":"string property",
                 "type":"string",
                 "value":"pytiled_parser rulez!1!!"
                }],
         "rotation":0,
         "type":"rectangle",
         "visible":true,
         "width":21.170853700125,
         "x":39.0678640445606,
         "y":131.826759122428
        }
        """,
        Rectangle(
            id=30,
            size=common_types.Size(21.170853700125, 13.7501420938956),
            name="name: rectangle - properties",
            rotation=0,
            type="rectangle",
            visible=True,
            coordinates=common_types.OrderedPair(39.0678640445606, 131.826759122428),
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
        {
                 "height":0,
                 "id":2,
                 "name":"name:  point",
                 "point":true,
                 "rotation":0,
                 "type":"point",
                 "visible":true,
                 "width":0,
                 "x":159.981811981357,
                 "y":82.9373650107991
        }
        """,
        Point(
            id=2,
            name="name:  point",
            rotation=0,
            type="point",
            visible=True,
            coordinates=common_types.OrderedPair(159.981811981357, 82.9373650107991),
        ),
    ),
    (
        """
        {
                 "height":0,
                 "id":3,
                 "name":"name:  point invisible",
                 "point":true,
                 "rotation":0,
                 "type":"point",
                 "visible":false,
                 "width":0,
                 "x":109.346368080027,
                 "y":95.8144822098443
        }
        """,
        Point(
            id=3,
            name="name:  point invisible",
            rotation=0,
            type="point",
            visible=False,
            coordinates=common_types.OrderedPair(109.346368080027, 95.8144822098443),
        ),
    ),
]

TILES = [
    (
        """
        {
         "gid":79,
         "height":32,
         "id":13,
         "name":"name: tile",
         "rotation":0,
         "type":"tile",
         "visible":true,
         "width":32,
         "x":111.898147095601,
         "y":48.3019211094691
        }
        """,
        Tile(
            id=13,
            size=common_types.Size(32, 32),
            name="name: tile",
            rotation=0,
            type="tile",
            visible=True,
            coordinates=common_types.OrderedPair(111.898147095601, 48.3019211094691),
            gid=79,
        ),
    ),
    (
        """
        {
         "gid":80,
         "height":32,
         "id":14,
         "name":"name: tile - invisible",
         "rotation":0,
         "type":"tile",
         "visible":false,
         "width":32,
         "x":41.1831306127089,
         "y":168.779356598841
        }
        """,
        Tile(
            id=14,
            size=common_types.Size(32, 32),
            name="name: tile - invisible",
            rotation=0,
            type="tile",
            visible=False,
            coordinates=common_types.OrderedPair(41.1831306127089, 168.779356598841),
            gid=80,
        ),
    ),
    (
        """
        {
         "gid":2147483742,
         "height":32,
         "id":15,
         "name":"name: tile - horizontal flipped",
         "rotation":0,
         "type":"tile",
         "visible":true,
         "width":32,
         "x":197.236330567239,
         "y":59.8695009662385
        }
        """,
        Tile(
            id=15,
            size=common_types.Size(32, 32),
            name="name: tile - horizontal flipped",
            rotation=0,
            type="tile",
            visible=True,
            coordinates=common_types.OrderedPair(197.236330567239, 59.8695009662385),
            gid=2147483742,
        ),
    ),
    (
        """
        {
         "gid":1073741918,
         "height":32,
         "id":16,
         "name":"name: tile - vertical flipped",
         "rotation":0,
         "type":"tile",
         "visible":true,
         "width":32,
         "x":32.4528816642037,
         "y":60.742525861089
        }
        """,
        Tile(
            id=16,
            size=common_types.Size(32, 32),
            name="name: tile - vertical flipped",
            rotation=0,
            type="tile",
            visible=True,
            coordinates=common_types.OrderedPair(32.4528816642037, 60.742525861089),
            gid=1073741918,
        ),
    ),
    (
        """
        {
         "gid":3221225558,
         "height":32,
         "id":17,
         "name":"name: tile - both flipped",
         "rotation":0,
         "type":"tile",
         "visible":true,
         "width":32,
         "x":167.553484142321,
         "y":95.6635216551097
        }
        """,
        Tile(
            id=17,
            size=common_types.Size(32, 32),
            name="name: tile - both flipped",
            rotation=0,
            type="tile",
            visible=True,
            coordinates=common_types.OrderedPair(167.553484142321, 95.6635216551097),
            gid=3221225558,
        ),
    ),
    (
        """
        {
         "gid":86,
         "height":32,
         "id":18,
         "name":"name: tile - rotated",
         "rotation":89,
         "type":"tile",
         "visible":true,
         "width":32,
         "x":85.65,
         "y":142.62
        }
        """,
        Tile(
            id=18,
            size=common_types.Size(32, 32),
            name="name: tile - rotated",
            rotation=89,
            type="tile",
            visible=True,
            coordinates=common_types.OrderedPair(85.65, 142.62),
            gid=86,
        ),
    ),
]

POLYGONS = [
    (
        """
        {
                 "height":0,
                 "id":9,
                 "name":"name: polygon",
                 "polygon":[
                        {
                         "x":0,
                         "y":0
                        },
                        {
                         "x":19.424803910424,
                         "y":27.063771740366
                        },
                        {
                         "x":19.6430601341366,
                         "y":3.05558713197681
                        },
                        {
                         "x":-2.61907468455156,
                         "y":15.9327043310219
                        },
                        {
                         "x":25.317721950665,
                         "y":16.3692167784472
                        }],
                 "rotation":0,
                 "type":"polygon",
                 "visible":true,
                 "width":0,
                 "x":89.485051722178,
                 "y":38.6313515971354
        }
        """,
        Polygon(
            id=9,
            name="name: polygon",
            points=[
                common_types.OrderedPair(0, 0),
                common_types.OrderedPair(19.424803910424, 27.063771740366),
                common_types.OrderedPair(19.6430601341366, 3.05558713197681),
                common_types.OrderedPair(-2.61907468455156, 15.9327043310219),
                common_types.OrderedPair(25.317721950665, 16.3692167784472),
            ],
            rotation=0,
            type="polygon",
            visible=True,
            coordinates=common_types.OrderedPair(89.485051722178, 38.6313515971354),
        ),
    ),
    (
        """
        {
                 "height":0,
                 "id":10,
                 "name":"name: polygon - invisible",
                 "polygon":[
                        {
                         "x":0,
                         "y":0
                        },
                        {
                         "x":-12.8771171990451,
                         "y":7.63896782994203
                        },
                        {
                         "x":-14.8414232124588,
                         "y":-10.2580425144936
                        }],
                 "rotation":0,
                 "type":"polygon",
                 "visible":false,
                 "width":0,
                 "x":133.791065135842,
                 "y":24.4446970558145
        }
        """,
        Polygon(
            id=10,
            name="name: polygon - invisible",
            points=[
                common_types.OrderedPair(0, 0),
                common_types.OrderedPair(-12.8771171990451, 7.63896782994203),
                common_types.OrderedPair(-14.8414232124588, -10.2580425144936),
            ],
            rotation=0,
            type="polygon",
            visible=False,
            coordinates=common_types.OrderedPair(133.791065135842, 24.4446970558145),
        ),
    ),
    (
        """
        {
                 "height":0,
                 "id":11,
                 "name":"name: polygon - rotated",
                 "polygon":[
                        {
                         "x":0,
                         "y":0
                        },
                        {
                         "x":-12.8771171990451,
                         "y":0
                        },
                        {
                         "x":-6.98419915880413,
                         "y":7.63896782994203
                        },
                        {
                         "x":-13.9683983176083,
                         "y":16.8057292258725
                        },
                        {
                         "x":3.71035580311468,
                         "y":15.277935659884
                        },
                        {
                         "x":-3.71035580311471,
                         "y":8.29373650107991
                        }],
                 "rotation":123,
                 "type":"polygon",
                 "visible":true,
                 "width":0,
                 "x":152.779356598841,
                 "y":19.8613163578493
        }
        """,
        Polygon(
            id=11,
            name="name: polygon - rotated",
            points=[
                common_types.OrderedPair(0, 0),
                common_types.OrderedPair(-12.8771171990451, 0),
                common_types.OrderedPair(-6.98419915880413, 7.63896782994203),
                common_types.OrderedPair(-13.9683983176083, 16.8057292258725),
                common_types.OrderedPair(3.71035580311468, 15.277935659884),
                common_types.OrderedPair(-3.71035580311471, 8.29373650107991),
            ],
            rotation=123,
            type="polygon",
            visible=True,
            coordinates=common_types.OrderedPair(152.779356598841, 19.8613163578493),
        ),
    ),
]

POLYLINES = [
    (
        """
        {
                 "height":0,
                 "id":12,
                 "name":"name: polyline",
                 "polyline":[
                        {
                         "x":0,
                         "y":0
                        },
                        {
                         "x":-13.3136296464704,
                         "y":41.0321700579743
                        },
                        {
                         "x":21.3891099238377,
                         "y":16.8057292258725
                        }],
                 "rotation":0,
                 "type":"polyline",
                 "visible":true,
                 "width":0,
                 "x":124.187791292486,
                 "y":90.1398203933159
        }
        """,
        Polyline(
            id=12,
            name="name: polyline",
            points=[
                common_types.OrderedPair(0, 0),
                common_types.OrderedPair(-13.3136296464704, 41.0321700579743),
                common_types.OrderedPair(21.3891099238377, 16.8057292258725),
            ],
            rotation=0,
            type="polyline",
            visible=True,
            coordinates=common_types.OrderedPair(124.187791292486, 90.1398203933159),
        ),
    ),
    (
        """
        {
                 "height":0,
                 "id":31,
                 "name":"name: polyline - invisible",
                 "polyline":[
                        {
                         "x":0,
                         "y":0
                        },
                        {
                         "x":-9,
                         "y":20.3333333333333
                        },
                        {
                         "x":5,
                         "y":23.6666666666667
                        }],
                 "rotation":0,
                 "type":"polyline",
                 "visible":false,
                 "width":0,
                 "x":140,
                 "y":163.333333333333
        }
        """,
        Polyline(
            id=31,
            name="name: polyline - invisible",
            points=[
                common_types.OrderedPair(0, 0),
                common_types.OrderedPair(-9, 20.3333333333333),
                common_types.OrderedPair(5, 23.6666666666667),
            ],
            rotation=0,
            type="polyline",
            visible=False,
            coordinates=common_types.OrderedPair(140, 163.333333333333),
        ),
    ),
    (
        """
        {
                 "height":0,
                 "id":32,
                 "name":"name: polyline - rotated",
                 "polyline":[
                        {
                         "x":0,
                         "y":0
                        },
                        {
                         "x":10.3333333333333,
                         "y":13
                        },
                        {
                         "x":-5.33333333333331,
                         "y":19.6666666666667
                        }],
                 "rotation":0,
                 "type":"polyline",
                 "visible":true,
                 "width":0,
                 "x":192.333333333333,
                 "y":128.666666666667
        }
        """,
        Polyline(
            id=32,
            name="name: polyline - rotated",
            points=[
                common_types.OrderedPair(0, 0),
                common_types.OrderedPair(10.3333333333333, 13),
                common_types.OrderedPair(-5.33333333333331, 19.6666666666667),
            ],
            rotation=0,
            type="polyline",
            visible=True,
            coordinates=common_types.OrderedPair(192.333333333333, 128.666666666667),
        ),
    ),
]

TEXTS = [
    (
        """
        {
                 "height":19,
                 "id":19,
                 "name":"name: text",
                 "rotation":0,
                 "text":
                    {
                     "text":"Hello World",
                     "wrap":true
                    },
                 "type":"text",
                 "visible":true,
                 "width":92.375,
                 "x":81.7106470956008,
                 "y":93.2986813686484
        }
        """,
        Text(
            id=19,
            name="name: text",
            text="Hello World",
            type="text",
            wrap=True,
            rotation=0,
            visible=True,
            size=common_types.Size(92.375, 19),
            coordinates=common_types.OrderedPair(81.7106470956008, 93.2986813686484),
        ),
    ),
    (
        """
        {
                 "height":19,
                 "id":20,
                 "name":"name: text - invisible",
                 "rotation":0,
                 "text":
                    {
                     "text":"Hello World",
                     "wrap":true
                    },
                 "type":"text",
                 "visible":false,
                 "width":92.375,
                 "x":8.37655592815732,
                 "y":112.068716607935
        }
        """,
        Text(
            id=20,
            name="name: text - invisible",
            text="Hello World",
            wrap=True,
            type="text",
            rotation=0,
            visible=False,
            size=common_types.Size(92.375, 19),
            coordinates=common_types.OrderedPair(8.37655592815732, 112.068716607935),
        ),
    ),
    (
        """
        {
                 "height":19,
                 "id":21,
                 "name":"name: text - rotated",
                 "rotation":19,
                 "text":
                    {
                     "text":"Hello World",
                     "wrap":true
                    },
                 "type":"text",
                 "visible":true,
                 "width":92.375,
                 "x":157.882069171308,
                 "y":78.4572581561896
        }
        """,
        Text(
            id=21,
            name="name: text - rotated",
            text="Hello World",
            wrap=True,
            rotation=19,
            type="text",
            visible=True,
            size=common_types.Size(92.375, 19),
            coordinates=common_types.OrderedPair(157.882069171308, 78.4572581561896),
        ),
    ),
    (
        """
        {
                 "height":19,
                 "id":22,
                 "name":"name: text - different font",
                 "rotation":0,
                 "text":
                    {
                     "bold":true,
                     "fontfamily":"DejaVu Sans",
                     "pixelsize":19,
                     "text":"Hello World",
                     "wrap":true
                    },
                 "type":"text",
                 "visible":true,
                 "width":92.375,
                 "x":2.70189411162896,
                 "y":101.592417869728
        }
        """,
        Text(
            id=22,
            name="name: text - different font",
            text="Hello World",
            wrap=True,
            bold=True,
            font_family="DejaVu Sans",
            font_size=19,
            rotation=0,
            type="text",
            visible=True,
            size=common_types.Size(92.375, 19),
            coordinates=common_types.OrderedPair(2.70189411162896, 101.592417869728),
        ),
    ),
    (
        """
        {
                 "height":19,
                 "id":23,
                 "name":"name: text - no word wrap",
                 "rotation":0,
                 "text":
                    {
                     "text":"Hello World"
                    },
                 "type":"text",
                 "visible":true,
                 "width":92.375,
                 "x":9.90434949414573,
                 "y":154.192167784472
        }
        """,
        Text(
            id=23,
            name="name: text - no word wrap",
            text="Hello World",
            rotation=0,
            type="text",
            visible=True,
            size=common_types.Size(92.375, 19),
            coordinates=common_types.OrderedPair(9.90434949414573, 154.192167784472),
        ),
    ),
    (
        """
        {
                 "height":19,
                 "id":24,
                 "name":"name: text - right bottom align",
                 "rotation":0,
                 "text":
                    {
                     "halign":"right",
                     "text":"Hello World",
                     "valign":"bottom",
                     "wrap":true
                    },
                 "type":"text",
                 "visible":true,
                 "width":92.375,
                 "x":151.989151131067,
                 "y":1.19455496191883
        }
        """,
        Text(
            id=24,
            name="name: text - right bottom align",
            text="Hello World",
            wrap=True,
            horizontal_align="right",
            vertical_align="bottom",
            rotation=0,
            type="text",
            visible=True,
            size=common_types.Size(92.375, 19),
            coordinates=common_types.OrderedPair(151.989151131067, 1.19455496191883),
        ),
    ),
    (
        """
        {
          "height": 19,
          "id": 25,
          "name": "text: center center align",
          "rotation": 0,
          "text": {
            "halign": "center",
            "text": "Hello World",
            "valign": "center",
            "wrap": true
          },
          "type": "text",
          "visible": true,
          "width": 92.375,
          "x": 4.22968767761736,
          "y": 3.81362964647039
        }
        """,
        Text(
            id=25,
            name="text: center center align",
            rotation=0,
            text="Hello World",
            wrap=True,
            horizontal_align="center",
            vertical_align="center",
            type="text",
            visible=True,
            size=common_types.Size(92.375, 19),
            coordinates=common_types.OrderedPair(4.22968767761736, 3.81362964647039),
        ),
    ),
    (
        """
        {
          "height": 19,
          "id": 26,
          "name": "name: text - justified",
          "rotation": 0,
          "text": {
            "halign": "justify",
            "text": "Hello World",
            "wrap": true
          },
          "type": "text",
          "visible": true,
          "width": 92.375,
          "x": 13.8329615209731,
          "y": 60.7785040354666
        }
        """,
        Text(
            id=26,
            name="name: text - justified",
            rotation=0,
            text="Hello World",
            wrap=True,
            horizontal_align="justify",
            type="text",
            visible=True,
            size=common_types.Size(92.375, 19),
            coordinates=common_types.OrderedPair(13.8329615209731, 60.7785040354666),
        ),
    ),
    (
        """
        {
          "height": 19,
          "id": 27,
          "name": "name: text - red",
          "rotation": 0,
          "text": {
            "color": "#aa0000",
            "text": "Hello World",
            "wrap": true
          },
          "type": "text",
          "visible": true,
          "width": 92.375,
          "x": 96.3338140843469,
          "y": 130.620495623508
        }
        """,
        Text(
            id=27,
            name="name: text - red",
            rotation=0,
            text="Hello World",
            wrap=True,
            color=common_types.Color(170, 0, 0, 255),
            type="text",
            visible=True,
            size=common_types.Size(92.375, 19),
            coordinates=common_types.OrderedPair(96.3338140843469, 130.620495623508),
        ),
    ),
    (
        """
        {
         "height":19,
         "id":31,
         "name":"name: text - font options",
         "rotation":0,
         "text":
            {
             "bold":true,
             "italic":true,
             "kerning":false,
             "strikeout":true,
             "text":"Hello World",
             "underline":true,
             "wrap":true
            },
         "type":"text",
         "visible":true,
         "width":92.375,
         "x":33,
         "y":22
        }
        """,
        Text(
            id=31,
            name="name: text - font options",
            rotation=0,
            bold=True,
            italic=True,
            kerning=False,
            strike_out=True,
            text="Hello World",
            underline=True,
            wrap=True,
            type="text",
            visible=True,
            size=common_types.Size(92.375, 19),
            coordinates=common_types.OrderedPair(33, 22),
        ),
    ),
]

OBJECTS = ELLIPSES + RECTANGLES + POINTS + TILES + POLYGONS + POLYLINES + TEXTS


@pytest.mark.parametrize("raw_object_json,expected", OBJECTS)
def test_parse_layer(raw_object_json, expected):
    raw_object = json.loads(raw_object_json)
    result = parse(raw_object)

    assert result == expected


def test_parse_no_parent_dir():

    raw_object = """
        {
        "id":1,
        "template": "mytemplate.json",
        "x":27.7185404115039,
        "y":23.571672160964
        }
        """

    json_object = json.loads(raw_object)
    with pytest.raises(RuntimeError):
        parse(json_object)
