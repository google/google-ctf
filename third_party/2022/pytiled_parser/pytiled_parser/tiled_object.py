# pylint: disable=too-few-public-methods
import xml.etree.ElementTree as etree
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import attr

from . import properties as properties_
from .common_types import Color, OrderedPair, Size


@attr.s(auto_attribs=True, kw_only=True)
class TiledObject:
    """TiledObject object.

    See:
        https://doc.mapeditor.org/en/stable/reference/tmx-map-format/#object

    Attributes:
        id_: Unique ID of the tiled object. Each tiled object that is placed on a map
            gets a unique id. Even if an tiled object was deleted, no tiled object gets
            the same ID.
        gid: Global tiled object ID.
        coordinates: The location of the tiled object in pixels.
        size: The width of the tiled object in pixels (default: (0, 0)).
        rotation: The rotation of the tiled object in degrees clockwise (default: 0).
        opacity: The opacity of the tiled object. (default: 1)
        name: The name of the tiled object.
        type: The type of the tiled object.
        properties: The properties of the TiledObject.
    """

    id: int

    coordinates: OrderedPair
    size: Size = Size(0, 0)
    rotation: float = 0
    visible: bool = True
    name: str = ""
    type: str = ""

    properties: properties_.Properties = {}


@attr.s()
class Ellipse(TiledObject):
    """Elipse shape defined by a point, width, height, and rotation.

    See: https://doc.mapeditor.org/en/stable/reference/tmx-map-format/#ellipse
    """


@attr.s()
class Point(TiledObject):
    """Point defined by a coordinate (x,y).

    See: https://doc.mapeditor.org/en/stable/reference/tmx-map-format/#point
    """


@attr.s(auto_attribs=True, kw_only=True)
class Polygon(TiledObject):
    """Polygon shape defined by a set of connections between points.

    See: https://doc.mapeditor.org/en/stable/reference/tmx-map-format/#polygon

    Attributes:
        points: FIXME
    """

    points: List[OrderedPair]


@attr.s(auto_attribs=True, kw_only=True)
class Polyline(TiledObject):
    """Polyline defined by a set of connections between points.

    See:
        https://doc.mapeditor.org/en/stable/reference/tmx-map-format/#polyline

    Attributes:
        points: List of coordinates relative to the location of the object.
    """

    points: List[OrderedPair]


@attr.s()
class Rectangle(TiledObject):
    """Rectangle shape defined by a point, width, and height.

    See: https://doc.mapeditor.org/en/stable/manual/objects/#insert-rectangle
        (objects in tiled are rectangles by default, so there is no specific
        documentation on the tmx-map-format page for it.)
    """


@attr.s(auto_attribs=True, kw_only=True)
class Text(TiledObject):
    """Text object with associated settings.

    See: https://doc.mapeditor.org/en/stable/reference/tmx-map-format/#text
        and https://doc.mapeditor.org/en/stable/manual/objects/#insert-text

    Attributes:
        font_family: The font family used (default: "sans-serif")
        font_size: The size of the font in pixels. (default: 16)
        wrap: Whether word wrapping is enabled. (default: False)
        color: Color of the text. (default: #000000)
        bold: Whether the font is bold. (default: False)
        italic: Whether the font is italic. (default: False)
        underline: Whether the text is underlined. (default: False)
        strike_out: Whether the text is striked-out. (default: False)
        kerning: Whether kerning should be used while rendering the text. (default:
            False)
        horizontal_align: Horizontal alignment of the text (default: "left")
        vertical_align: Vertical alignment of the text (defalt: "top")
    """

    text: str
    color: Color = Color(255, 255, 255, 255)

    font_family: str = "sans-serif"
    font_size: float = 16

    bold: bool = False
    italic: bool = False
    kerning: bool = True
    strike_out: bool = False
    underline: bool = False

    horizontal_align: str = "left"
    vertical_align: str = "top"
    wrap: bool = False


@attr.s(auto_attribs=True, kw_only=True)
class Tile(TiledObject):
    """Tile object

    See: https://doc.mapeditor.org/en/stable/manual/objects/#insert-tile

    Attributes:
        gid: Reference to a global tile id.
    """

    gid: int
    new_tileset: Optional[Union[etree.Element, Dict[str, Any]]] = None
    new_tileset_path: Optional[Path] = None
