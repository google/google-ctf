# pylint: disable=too-few-public-methods
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional

import attr

from . import layer
from . import properties as properties_
from .common_types import Color, OrderedPair
from .wang_set import WangSet


class Grid(NamedTuple):
    """Contains info for isometric maps.

    This element is only used in case of isometric orientation, and determines how tile
        overlays for terrain and collision information are rendered.

    Args:
        orientation: Orientation of the grid for the tiles in this tileset (orthogonal
            or isometric).
        width: Width of a grid cell.
        height: Height of a grid cell.
    """

    orientation: str
    width: int
    height: int


class Frame(NamedTuple):
    """Animation Frame object.

    This is only used as a part of an animation for Tile objects.

    Args:
        tile_id: The local ID of a tile within the parent tile set object.
        duration: How long in milliseconds this frame should be displayed before
            advancing to the next frame.
    """

    tile_id: int
    duration: int


@attr.s(auto_attribs=True, kw_only=True)
class Transformations:
    """Transformations Object.

    This is used to store what transformations may be performed on Tiles
    within a tileset. (This is primarily used with wang sets, however could
    be used for any means a game wants really.)

    Args:
        hflip: Allow horizontal flip?
        vflip: Allow vertical flip?
        rotate: Allow rotation?
        prefer_untransformed: Should untransformed tiles be preferred?
    """

    hflip: Optional[bool] = None
    vflip: Optional[bool] = None
    rotate: Optional[bool] = None
    prefer_untransformed: Optional[bool] = None


@attr.s(auto_attribs=True, kw_only=True)
class Tile:
    # FIXME: args
    """Individual tile object.

    See: https://doc.mapeditor.org/en/stable/reference/tmx-map-format/#tile

    Args:
        id: The local tile ID within its tileset.
        type: The type of the tile. Refers to an object type and is used by tile
            objects.
        terrain: Defines the terrain type of each corner of the tile.
        animation: Each tile can have exactly one animation associated with it.
    """

    id: int
    opacity: int = 1
    type: Optional[str] = None
    animation: Optional[List[Frame]] = None
    objects: Optional[layer.Layer] = None
    image: Optional[Path] = None
    image_width: Optional[int] = None
    image_height: Optional[int] = None
    properties: Optional[properties_.Properties] = None
    tileset: Optional["Tileset"] = None
    flipped_horizontally: bool = False
    flipped_diagonally: bool = False
    flipped_vertically: bool = False


@attr.s(auto_attribs=True)
class Tileset:
    """Object for storing a TSX with all associated collision data.

    Args:
        name: The name of this tileset.
        max_tile_size: The maximum size of a tile in this tile set in pixels.
        spacing: The spacing in pixels between the tiles in this tileset (applies to
            the tileset image).
        margin: The margin around the tiles in this tileset (applies to the tileset
            image).
        tile_count: The number of tiles in this tileset.
        columns: The number of tile columns in the tileset. For image collection
            tilesets it is editable and is used when displaying the tileset.
        grid: Only used in case of isometric orientation, and determines how tile
            overlays for terrain and collision information are rendered.
        tileoffset: Used to specify an offset in pixels when drawing a tile from the
            tileset. When not present, no offset is applied.
        image: Used for spritesheet tile sets.
        tiles: Dict of Tile objects by Tile.id.
        tsx_file: Path of the file containing the tileset, None if loaded internally
            from a map
        parent_dir: Path of the parent directory of the file containing the tileset,
            None if loaded internally from a map
    """

    name: str
    tile_width: int
    tile_height: int

    tile_count: int
    columns: int

    firstgid: int

    type: str = "tileset"

    spacing: int = 0
    margin: int = 0

    tiled_version: Optional[str] = None
    version: Optional[str] = None

    image: Optional[Path] = None
    image_width: Optional[int] = None
    image_height: Optional[int] = None

    transformations: Optional[Transformations] = None

    background_color: Optional[Color] = None
    tile_offset: Optional[OrderedPair] = None
    transparent_color: Optional[Color] = None
    grid: Optional[Grid] = None
    properties: Optional[properties_.Properties] = None
    tiles: Optional[Dict[int, Tile]] = None
    wang_sets: Optional[List[WangSet]] = None
    alignment: Optional[str] = None
