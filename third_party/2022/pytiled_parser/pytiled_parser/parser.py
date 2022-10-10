from pathlib import Path

from pytiled_parser import UnknownFormat
from pytiled_parser.parsers.json.tiled_map import parse as json_map_parse
from pytiled_parser.parsers.tmx.tiled_map import parse as tmx_map_parse
from pytiled_parser.tiled_map import TiledMap
from pytiled_parser.util import check_format


def parse_map(file: Path) -> TiledMap:
    """Parse the raw Tiled map into a pytiled_parser type

    Args:
        file: Path to the map file

    Returns:
        Tiledmap: a properly typed TiledMap
    """
    parser = check_format(file)

    # The type ignores are because mypy for some reaosn thinks those functions return Any
    if parser == "tmx":
        return tmx_map_parse(file)  # type: ignore
    elif parser == "json":
        return json_map_parse(file)  # type: ignore
    else:
        raise UnknownFormat(
            "Unknown Map Format, please use either the TMX or JSON format."
        )
