"""Layer parsing for the JSON Map Format.
"""
import base64
import gzip
import importlib.util
import zlib
from pathlib import Path
from typing import Any, List, Optional, Union, cast

from typing_extensions import TypedDict

from pytiled_parser.common_types import OrderedPair, Size
from pytiled_parser.layer import (
    Chunk,
    ImageLayer,
    Layer,
    LayerGroup,
    ObjectLayer,
    TileLayer,
)
from pytiled_parser.parsers.json.properties import RawProperty
from pytiled_parser.parsers.json.properties import parse as parse_properties
from pytiled_parser.parsers.json.tiled_object import RawObject
from pytiled_parser.parsers.json.tiled_object import parse as parse_object
from pytiled_parser.util import parse_color

zstd_spec = importlib.util.find_spec("zstd")
if zstd_spec:
    import zstd
else:
    zstd = None


class RawChunk(TypedDict):
    """The keys and their types that appear in a Tiled JSON Chunk Object.

    Tiled Doc: https://doc.mapeditor.org/en/stable/reference/json-map-format/#chunk
    """

    data: Union[List[int], str]
    height: int
    width: int
    x: int
    y: int


class RawLayer(TypedDict):
    """The keys and their types that appear in a Tiled JSON Layer Object.

    Tiled Doc: https://doc.mapeditor.org/en/stable/reference/json-map-format/#layer
    """

    chunks: List[RawChunk]
    compression: str
    data: Union[List[int], str]
    draworder: str
    encoding: str
    height: int
    id: int
    image: str
    layers: List[Any]
    name: str
    objects: List[RawObject]
    offsetx: float
    offsety: float
    parallaxx: float
    parallaxy: float
    opacity: float
    properties: List[RawProperty]
    startx: int
    starty: int
    tintcolor: str
    transparentcolor: str
    type: str
    visible: bool
    width: int
    x: int
    y: int


def _convert_raw_tile_layer_data(data: List[int], layer_width: int) -> List[List[int]]:
    """Convert raw layer data into a nested lit based on the layer width

    Args:
        data: The data to convert
        layer_width: Width of the layer

    Returns:
        List[List[int]]: A nested list containing the converted data
    """
    tile_grid: List[List[int]] = [[]]

    column_count = 0
    row_count = 0
    for item in data:
        column_count += 1
        tile_grid[row_count].append(item)
        if not column_count % layer_width and column_count < len(data):
            row_count += 1
            tile_grid.append([])

    return tile_grid


def _decode_tile_layer_data(
    data: str, compression: str, layer_width: int
) -> List[List[int]]:
    """Decode Base64 Encoded tile data. Optionally supports gzip and zlib compression.

    Args:
        data: The base64 encoded data
        compression: Either zlib, gzip, or empty. If empty no decompression is done.

    Returns:
        List[List[int]]: A nested list containing the decoded data

    Raises:
        ValueError: For an unsupported compression type.
    """
    unencoded_data = base64.b64decode(data)
    if compression == "zlib":
        unzipped_data = zlib.decompress(unencoded_data)
    elif compression == "gzip":
        unzipped_data = gzip.decompress(unencoded_data)
    elif compression == "zstd" and zstd is None:
        raise ValueError(
            "zstd compression support is not installed."
            "To install use 'pip install pytiled-parser[zstd]'"
        )
    elif compression == "zstd":
        unzipped_data = zstd.decompress(unencoded_data)
    else:
        unzipped_data = unencoded_data

    tile_grid: List[int] = []

    byte_count = 0
    int_count = 0
    int_value = 0
    for byte in unzipped_data:
        int_value += byte << (byte_count * 8)
        byte_count += 1
        if not byte_count % 4:
            byte_count = 0
            int_count += 1
            tile_grid.append(int_value)
            int_value = 0

    return _convert_raw_tile_layer_data(tile_grid, layer_width)


def _parse_chunk(
    raw_chunk: RawChunk,
    encoding: Optional[str] = None,
    compression: Optional[str] = None,
) -> Chunk:
    """Parse the raw_chunk to a Chunk.

    Args:
        raw_chunk: RawChunk to be parsed to a Chunk
        encoding: Encoding type. ("base64" or None)
        compression: Either zlib, gzip, or empty. If empty no decompression is done.

    Returns:
        Chunk: The Chunk created from the raw_chunk
    """
    if encoding == "base64":
        assert isinstance(compression, str)
        assert isinstance(raw_chunk["data"], str)
        data = _decode_tile_layer_data(
            raw_chunk["data"], compression, raw_chunk["width"]
        )
    else:
        data = _convert_raw_tile_layer_data(
            raw_chunk["data"], raw_chunk["width"]  # type: ignore
        )

    chunk = Chunk(
        coordinates=OrderedPair(raw_chunk["x"], raw_chunk["y"]),
        size=Size(raw_chunk["width"], raw_chunk["height"]),
        data=data,
    )

    return chunk


def _parse_common(raw_layer: RawLayer) -> Layer:
    """Create a Layer containing all the attributes common to all layer types.

    This is to create the stub Layer object that can then be used to create the actual
        specific sub-classes of Layer.

    Args:
        raw_layer: Raw layer get common attributes from

    Returns:
        Layer: The attributes in common of all layer types
    """
    common = Layer(
        name=raw_layer["name"],
        opacity=raw_layer["opacity"],
        visible=raw_layer["visible"],
    )

    # if startx is present, starty is present
    if raw_layer.get("startx") is not None:
        common.coordinates = OrderedPair(raw_layer["startx"], raw_layer["starty"])

    if raw_layer.get("id") is not None:
        common.id = raw_layer["id"]

    # if either width or height is present, they both are
    if raw_layer.get("width") is not None:
        common.size = Size(raw_layer["width"], raw_layer["height"])

    if raw_layer.get("offsetx") is not None:
        common.offset = OrderedPair(raw_layer["offsetx"], raw_layer["offsety"])

    if raw_layer.get("properties") is not None:
        common.properties = parse_properties(raw_layer["properties"])

    parallax = [1.0, 1.0]

    if raw_layer.get("parallaxx") is not None:
        parallax[0] = raw_layer["parallaxx"]

    if raw_layer.get("parallaxy") is not None:
        parallax[1] = raw_layer["parallaxy"]

    common.parallax_factor = OrderedPair(parallax[0], parallax[1])

    if raw_layer.get("tintcolor") is not None:
        common.tint_color = parse_color(raw_layer["tintcolor"])

    return common


def _parse_tile_layer(raw_layer: RawLayer) -> TileLayer:
    """Parse the raw_layer to a TileLayer.

    Args:
        raw_layer: RawLayer to be parsed to a TileLayer.

    Returns:
        TileLayer: The TileLayer created from raw_layer
    """
    tile_layer = TileLayer(**_parse_common(raw_layer).__dict__)

    if raw_layer.get("chunks") is not None:
        tile_layer.chunks = []
        for chunk in raw_layer["chunks"]:
            if raw_layer.get("encoding") is not None:
                tile_layer.chunks.append(
                    _parse_chunk(chunk, raw_layer["encoding"], raw_layer["compression"])
                )
            else:
                tile_layer.chunks.append(_parse_chunk(chunk))

    if raw_layer.get("data") is not None:
        if raw_layer.get("encoding") is not None:
            tile_layer.data = _decode_tile_layer_data(
                data=cast(str, raw_layer["data"]),
                compression=raw_layer["compression"],
                layer_width=raw_layer["width"],
            )
        else:
            tile_layer.data = _convert_raw_tile_layer_data(
                raw_layer["data"], raw_layer["width"]  # type: ignore
            )

    return tile_layer


def _parse_object_layer(
    raw_layer: RawLayer,
    parent_dir: Optional[Path] = None,
) -> ObjectLayer:
    """Parse the raw_layer to an ObjectLayer.

    Args:
        raw_layer: RawLayer to be parsed to an ObjectLayer.

    Returns:
        ObjectLayer: The ObjectLayer created from raw_layer
    """
    objects = []
    for object_ in raw_layer["objects"]:
        objects.append(parse_object(object_, parent_dir))

    return ObjectLayer(
        tiled_objects=objects,
        draw_order=raw_layer["draworder"],
        **_parse_common(raw_layer).__dict__,
    )


def _parse_image_layer(raw_layer: RawLayer) -> ImageLayer:
    """Parse the raw_layer to an ImageLayer.

    Args:
        raw_layer: RawLayer to be parsed to an ImageLayer.

    Returns:
        ImageLayer: The ImageLayer created from raw_layer
    """
    image_layer = ImageLayer(
        image=Path(raw_layer["image"]), **_parse_common(raw_layer).__dict__
    )

    if raw_layer.get("transparentcolor") is not None:
        image_layer.transparent_color = parse_color(raw_layer["transparentcolor"])

    return image_layer


def _parse_group_layer(
    raw_layer: RawLayer, parent_dir: Optional[Path] = None
) -> LayerGroup:
    """Parse the raw_layer to a LayerGroup.

    Args:
        raw_layer: RawLayer to be parsed to a LayerGroup.

    Returns:
        LayerGroup: The LayerGroup created from raw_layer
    """
    layers = []

    for layer in raw_layer["layers"]:
        layers.append(parse(layer, parent_dir=parent_dir))

    return LayerGroup(layers=layers, **_parse_common(raw_layer).__dict__)


def parse(
    raw_layer: RawLayer,
    parent_dir: Optional[Path] = None,
) -> Layer:
    """Parse a raw Layer into a pytiled_parser object.

    This function will determine the type of layer and parse accordingly.

    Args:
        raw_layer: Raw layer to be parsed.
        parent_dir: The parent directory that the map file is in.

    Returns:
        Layer: A parsed Layer.

    Raises:
        RuntimeError: For an invalid layer type being provided
    """
    type_ = raw_layer["type"]

    if type_ == "objectgroup":
        return _parse_object_layer(raw_layer, parent_dir)
    elif type_ == "group":
        return _parse_group_layer(raw_layer, parent_dir)
    elif type_ == "imagelayer":
        return _parse_image_layer(raw_layer)
    elif type_ == "tilelayer":
        return _parse_tile_layer(raw_layer)

    raise RuntimeError(f"An invalid layer type of {type_} was supplied")
