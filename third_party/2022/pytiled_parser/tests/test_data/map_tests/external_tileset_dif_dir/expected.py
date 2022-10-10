from pathlib import Path

from pytiled_parser import common_types, layer, tiled_map, tiled_object, tileset

EXPECTED = tiled_map.TiledMap(
    infinite=False,
    map_size=common_types.Size(8, 6),
    next_layer_id=3,
    next_object_id=1,
    orientation="orthogonal",
    render_order="right-down",
    tiled_version="1.6.0",
    tile_size=common_types.Size(32, 32),
    version="1.6",
    background_color=common_types.Color(255, 0, 4, 255),
    layers=[
        layer.TileLayer(
            name="Layer 1",
            opacity=1,
            visible=True,
            id=2,
            size=common_types.Size(8, 6),
            data=[
                [4, 3, 2, 1, 0, 0, 0, 0],
                [
                    0,
                    0,
                    0,
                    0,
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
                    0,
                    0,
                    0,
                    0,
                ],
            ],
        ),
    ],
    tilesets={
        1: tileset.Tileset(
            columns=0,
            margin=0,
            spacing=0,
            name="tileset",
            tile_count=4,
            tiled_version="1.6.0",
            tile_height=32,
            tile_width=32,
            firstgid=1,
            version="1.6",
            type="tileset",
            grid=tileset.Grid(orientation="orthogonal", width=1, height=1),
            tiles={
                0: tileset.Tile(
                    animation=[
                        tileset.Frame(duration=100, tile_id=0),
                        tileset.Frame(duration=100, tile_id=1),
                        tileset.Frame(duration=100, tile_id=2),
                        tileset.Frame(duration=100, tile_id=3),
                    ],
                    id=0,
                    image=Path(Path(__file__).parent / "../../images/tile_01.png")
                    .absolute()
                    .resolve(),
                    image_height=32,
                    image_width=32,
                    properties={"float property": 2.2},
                    type="tile",
                ),
                1: tileset.Tile(
                    id=1,
                    image=Path(Path(__file__).parent / "../../images/tile_02.png")
                    .absolute()
                    .resolve(),
                    image_height=32,
                    image_width=32,
                    objects=layer.ObjectLayer(
                        name="",
                        opacity=1,
                        visible=True,
                        draw_order="index",
                        tiled_objects=[
                            tiled_object.Rectangle(
                                id=2,
                                name="",
                                size=common_types.Size(
                                    14.4766410408043, 13.7196924896511
                                ),
                                rotation=0,
                                type="",
                                visible=True,
                                coordinates=common_types.OrderedPair(
                                    13.4358367829687, 13.5304553518628
                                ),
                            ),
                            tiled_object.Ellipse(
                                id=3,
                                name="",
                                size=common_types.Size(
                                    14.287403903016, 11.070372560615
                                ),
                                rotation=0,
                                type="",
                                visible=True,
                                coordinates=common_types.OrderedPair(
                                    13.8143110585452, 1.98698994677705
                                ),
                            ),
                        ],
                    ),
                    properties={"string property": "testing"},
                    type="tile",
                ),
                2: tileset.Tile(
                    id=2,
                    image=Path(Path(__file__).parent / "../../images/tile_03.png")
                    .absolute()
                    .resolve(),
                    image_height=32,
                    image_width=32,
                    properties={"bool property": True},
                    type="tile",
                ),
                3: tileset.Tile(
                    id=3,
                    image=Path(Path(__file__).parent / "../../images/tile_04.png")
                    .absolute()
                    .resolve(),
                    image_height=32,
                    image_width=32,
                    type="tile",
                ),
            },
        )
    },
    properties={
        "bool property - true": True,
        "color property": common_types.Color(73, 252, 255, 255),
        "file property": Path("../../../../../../var/log/syslog"),
        "float property": 1.23456789,
        "int property": 13,
        "string property": "Hello, World!!",
    },
)
