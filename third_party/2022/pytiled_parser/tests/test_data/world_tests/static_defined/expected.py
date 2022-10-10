from pathlib import Path

from pytiled_parser import common_types, layer, tiled_map, tileset, world

EXPECTED = world.World(
    only_show_adjacent=False,
    maps=[
        world.WorldMap(
            size=common_types.Size(160, 160),
            coordinates=common_types.OrderedPair(0, 0),
            tiled_map=tiled_map.TiledMap(
                map_file=Path(Path(__file__).parent / "map_01.json")
                .absolute()
                .resolve(),
                infinite=False,
                map_size=common_types.Size(5, 5),
                next_layer_id=2,
                next_object_id=1,
                orientation="orthogonal",
                render_order="right-down",
                tiled_version="1.6.0",
                tile_size=common_types.Size(32, 32),
                version="1.6",
                tilesets={
                    1: tileset.Tileset(
                        columns=8,
                        image=Path(
                            Path(__file__).parent
                            / "../../images/tmw_desert_spacing.png"
                        )
                        .absolute()
                        .resolve(),
                        image_width=265,
                        image_height=199,
                        firstgid=1,
                        margin=1,
                        spacing=1,
                        name="tileset",
                        tile_count=48,
                        tiled_version="1.6.0",
                        tile_height=32,
                        tile_width=32,
                        version="1.6",
                        type="tileset",
                    )
                },
                layers=[
                    layer.TileLayer(
                        name="Tile Layer 1",
                        opacity=1,
                        visible=True,
                        id=1,
                        size=common_types.Size(5, 5),
                        data=[
                            [30, 30, 30, 30, 30],
                            [30, 30, 30, 30, 30],
                            [30, 30, 30, 30, 30],
                            [30, 30, 30, 30, 30],
                            [30, 30, 30, 30, 30],
                        ],
                    )
                ],
            ),
        ),
        world.WorldMap(
            size=common_types.Size(160, 160),
            coordinates=common_types.OrderedPair(160, 0),
            tiled_map=tiled_map.TiledMap(
                map_file=Path(Path(__file__).parent / "map_02.json")
                .absolute()
                .resolve(),
                infinite=False,
                map_size=common_types.Size(5, 5),
                next_layer_id=2,
                next_object_id=1,
                orientation="orthogonal",
                render_order="right-down",
                tiled_version="1.6.0",
                tile_size=common_types.Size(32, 32),
                version="1.6",
                tilesets={
                    1: tileset.Tileset(
                        columns=8,
                        image=Path(
                            Path(__file__).parent
                            / "../../images/tmw_desert_spacing.png"
                        )
                        .absolute()
                        .resolve(),
                        image_width=265,
                        image_height=199,
                        firstgid=1,
                        margin=1,
                        spacing=1,
                        name="tileset",
                        tile_count=48,
                        tiled_version="1.6.0",
                        tile_height=32,
                        tile_width=32,
                        version="1.6",
                        type="tileset",
                    )
                },
                layers=[
                    layer.TileLayer(
                        name="Tile Layer 1",
                        opacity=1,
                        visible=True,
                        id=1,
                        size=common_types.Size(5, 5),
                        data=[
                            [30, 30, 30, 30, 30],
                            [30, 30, 30, 30, 30],
                            [30, 30, 30, 30, 30],
                            [30, 30, 30, 30, 30],
                            [30, 30, 30, 30, 30],
                        ],
                    )
                ],
            ),
        ),
    ],
)
