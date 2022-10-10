from pathlib import Path

from pytiled_parser import common_types, tiled_map, tileset

EXPECTED = tiled_map.TiledMap(
    infinite=False,
    layers=[],
    map_size=common_types.Size(8, 6),
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
            image=Path(Path(__file__).parent / "../../images/tmw_desert_spacing.png")
            .absolute()
            .resolve(),
            image_width=265,
            image_height=199,
            firstgid=1,
            margin=1,
            spacing=1,
            name="tile_set_image",
            tile_count=48,
            tiled_version="1.6.0",
            tile_height=32,
            tile_width=32,
            version="1.6",
            type="tileset",
        )
    },
)
