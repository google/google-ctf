from typing import Dict, List, Optional

import attr

from pytiled_parser.common_types import Color
from pytiled_parser.properties import Properties


@attr.s(auto_attribs=True)
class WangTile:

    tile_id: int
    wang_id: List[int]


@attr.s(auto_attribs=True)
class WangColor:

    color: Color
    name: str
    probability: float
    tile: int
    properties: Optional[Properties] = None


@attr.s(auto_attribs=True)
class WangSet:

    name: str
    tile: int
    wang_type: str
    wang_tiles: Dict[int, WangTile]
    wang_colors: List[WangColor]
    properties: Optional[Properties] = None
