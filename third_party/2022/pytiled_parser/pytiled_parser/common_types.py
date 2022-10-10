"""Module containing types that are common to other modules."""

# pylint: disable=too-few-public-methods

from typing import NamedTuple

import attr


class Color(NamedTuple):
    """Color NamedTuple.

    Attributes:
        red: Red, between 1 and 255.
        green: Green, between 1 and 255.
        blue: Blue, between 1 and 255.
        alpha: Alpha, between 1 and 255.
    """

    red: int
    green: int
    blue: int
    alpha: int


@attr.s(auto_attribs=True)
class Template:
    """FIXME TODO"""


class Size(NamedTuple):
    """Size NamedTuple.

    Attributes:
        width: The width of the object in pixels.
        height: The height of the object in pixels.
    """

    width: float
    height: float


class OrderedPair(NamedTuple):
    """OrderedPair NamedTuple.

    Attributes:
        x: X coordinate.
        y: Y coordinate.
    """

    x: float
    y: float
