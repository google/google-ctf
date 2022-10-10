"""This module handles parsing all types of layers.

See:
    - https://doc.mapeditor.org/en/stable/reference/json-map-format/#layer
    - https://doc.mapeditor.org/en/stable/manual/layers/
    - https://doc.mapeditor.org/en/stable/manual/editing-tile-layers/
"""

# pylint: disable=too-few-public-methods

from pathlib import Path
from typing import List, Optional, Union

import attr

from pytiled_parser.common_types import Color, OrderedPair, Size
from pytiled_parser.properties import Properties
from pytiled_parser.tiled_object import TiledObject


@attr.s(auto_attribs=True, kw_only=True)
class Layer:
    """Class that all layers inherit from.

    See: https://doc.mapeditor.org/en/stable/reference/json-map-format/#layer

    Attributes:
        name: The name of the layer object.
        opacity: Decimal value between 0 and 1 to determine opacity. 1 is completely
            opaque, 0 is completely transparent.
        visible: If the layer is visible in the Tiled Editor. (Do not use for games)
        coordinates: Where layer content starts in tiles. (For infinite maps)
        id: Unique ID of the layer. Each layer that added to a map gets a unique id.
            Even if a layer is deleted, no layer ever gets the same ID.
        size: Ordered pair of size of map in tiles.
        offset: Rendering offset of the layer object in pixels.
        properties: Properties for the layer.
    """

    name: str
    opacity: float = 1
    visible: bool = True

    coordinates: OrderedPair = OrderedPair(0, 0)
    parallax_factor: OrderedPair = OrderedPair(1, 1)
    offset: OrderedPair = OrderedPair(0, 0)

    id: Optional[int] = None
    size: Optional[Size] = None
    properties: Optional[Properties] = None
    tint_color: Optional[Color] = None


TileLayerGrid = List[List[int]]


@attr.s(auto_attribs=True)
class Chunk:
    """Chunk object for infinite maps.

    See: https://doc.mapeditor.org/en/stable/reference/json-map-format/#chunk

    Attributes:
        coordinates: Location of chunk in tiles.
        size: The size of the chunk in tiles.
        data: The global tile IDs in chunky according to row.
    """

    coordinates: OrderedPair
    size: Size
    data: List[List[int]]


# The tile data for one layer.
#
# Either a 2 dimensional array of integers representing the global tile IDs
#     for a TileLayerGrid, or a list of chunks for an infinite map layer.
LayerData = Union[TileLayerGrid, List[Chunk]]


@attr.s(auto_attribs=True, kw_only=True)
class TileLayer(Layer):
    """Tile map layer containing tiles.

    See:
        https://doc.mapeditor.org/en/stable/reference/json-map-format/#tile-layer-example

    Attributes:
        chunks: list of chunks (infinite maps)
        data: Either an 2 dimensional array of integers representing the global tile
            IDs for the map layer, or a list of chunks for an infinite map.
    """

    chunks: Optional[List[Chunk]] = None
    data: Optional[List[List[int]]] = None


@attr.s(auto_attribs=True, kw_only=True)
class ObjectLayer(Layer):
    """TiledObject Group Object.

    The object group is in fact a map layer, and is hence called "object layer" in
        Tiled.

    See:
        https://doc.mapeditor.org/en/stable/reference/json-map-format/#object-layer-example

    Attributes:
        tiled_objects: List of tiled_objects in the layer.
        draworder: Whether the objects are drawn according to the order of the object
            elements in the object group element ('manual'), or sorted by their
            y-coordinate ('topdown'). Defaults to 'topdown'. See:
            https://doc.mapeditor.org/en/stable/manual/objects/#changing-stacking-order
            for more info.
    """

    tiled_objects: List[TiledObject]

    draw_order: Optional[str] = "topdown"


@attr.s(auto_attribs=True, kw_only=True)
class ImageLayer(Layer):
    """Map layer containing images.

    See: https://doc.mapeditor.org/en/stable/manual/layers/#image-layers

    Attributes:
        image: The image used by this layer.
        transparent_color: Color that is to be made transparent on this layer.
    """

    image: Path
    transparent_color: Optional[Color] = None


@attr.s(auto_attribs=True, kw_only=True)
class LayerGroup(Layer):
    """A layer that contains layers (potentially including other LayerGroups).

    Offset and opacity recursively affect child layers.

    See:
        - https://doc.mapeditor.org/en/stable/reference/json-map-format/#layer
        - https://doc.mapeditor.org/en/stable/manual/layers/#group-layers

    Attributes:
        Layers: list of layers contained in the group.
    """

    layers: Optional[List[Layer]]
