from pathlib import Path

from pytiled_parser import common_types, layer, tiled_object

EXPECTED = [
    layer.TileLayer(
        name="Tile Layer 1",
        opacity=1,
        visible=True,
        id=1,
        size=common_types.Size(16, 16),
        offset=common_types.OrderedPair(163.089434111595, 116.462603878116),
        properties={
            "test": "test property",
        },
        chunks=[
            layer.Chunk(
                coordinates=common_types.OrderedPair(0, 0),
                size=common_types.Size(4, 8),
                data=[
                    [
                        1,
                        2,
                        3,
                        4,
                    ],
                    [
                        9,
                        10,
                        11,
                        12,
                    ],
                    [
                        17,
                        18,
                        19,
                        20,
                    ],
                    [
                        25,
                        26,
                        27,
                        28,
                    ],
                    [
                        33,
                        34,
                        35,
                        36,
                    ],
                    [
                        41,
                        42,
                        43,
                        44,
                    ],
                    [
                        0,
                        0,
                        0,
                        0,
                    ],
                    [
                        0,
                        0,
                        0,
                        0,
                    ],
                ],
            ),
            layer.Chunk(
                coordinates=common_types.OrderedPair(4, 0),
                size=common_types.Size(4, 8),
                data=[
                    [
                        5,
                        6,
                        7,
                        8,
                    ],
                    [
                        13,
                        14,
                        15,
                        16,
                    ],
                    [
                        21,
                        22,
                        23,
                        24,
                    ],
                    [
                        29,
                        30,
                        31,
                        32,
                    ],
                    [
                        37,
                        38,
                        39,
                        40,
                    ],
                    [
                        45,
                        46,
                        47,
                        48,
                    ],
                    [
                        0,
                        0,
                        0,
                        0,
                    ],
                    [
                        0,
                        0,
                        0,
                        0,
                    ],
                ],
            ),
        ],
    )
]
