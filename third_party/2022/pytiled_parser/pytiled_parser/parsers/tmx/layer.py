"""Layer parsing for the TMX Map Format.
"""
import base64
import gzip
import importlib.util
import xml.etree.ElementTree as etree
import zlib
from pathlib import Path
from typing import List, Optional

from pytiled_parser.common_types import OrderedPair, Size
from pytiled_parser.layer import (
    Chunk,
    ImageLayer,
    Layer,
    LayerGroup,
    ObjectLayer,
    TileLayer,
)
from pytiled_parser.parsers.tmx.properties import parse as parse_properties
from pytiled_parser.parsers.tmx.tiled_object import parse as parse_object
from pytiled_parser.util import parse_color

zstd_spec = importlib.util.find_spec("zstd")
if zstd_spec:
    import zstd
else:
    zstd = None


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
    raw_chunk: etree.Element,
    encoding: Optional[str] = None,
    compression: Optional[str] = None,
) -> Chunk:
    """Parse the raw_chunk to a Chunk.

    Args:
        raw_chunk: XML Element to be parsed to a Chunk
        encoding: Encoding type. ("base64" or None)
        compression: Either zlib, gzip, or empty. If empty no decompression is done.

    Returns:
        Chunk: The Chunk created from the raw_chunk
    """
    if encoding == "base64":
        assert isinstance(compression, str)
        data = _decode_tile_layer_data(
            raw_chunk.text, compression, int(raw_chunk.attrib["width"])  # type: ignore
        )
    else:
        data = _convert_raw_tile_layer_data(
            [int(v.strip()) for v in raw_chunk.text.split(",")],  # type: ignore
            int(raw_chunk.attrib["width"]),
        )

    return Chunk(
        coordinates=OrderedPair(int(raw_chunk.attrib["x"]), int(raw_chunk.attrib["y"])),
        size=Size(int(raw_chunk.attrib["width"]), int(raw_chunk.attrib["height"])),
        data=data,
    )


def _parse_common(raw_layer: etree.Element) -> Layer:
    """Create a Layer containing all the attributes common to all layer types.

    This is to create the stub Layer object that can then be used to create the actual
        specific sub-classes of Layer.

    Args:
        raw_layer: XML Element to get common attributes from

    Returns:
        Layer: The attributes in common of all layer types
    """
    if raw_layer.attrib.get("name") is None:
        raw_layer.attrib["name"] = ""

    common = Layer(
        name=raw_layer.attrib["name"],
    )

    if raw_layer.attrib.get("opacity") is not None:
        common.opacity = float(raw_layer.attrib["opacity"])

    if raw_layer.attrib.get("visible") is not None:
        common.visible = bool(int(raw_layer.attrib["visible"]))

    if raw_layer.attrib.get("id") is not None:
        common.id = int(raw_layer.attrib["id"])

    if raw_layer.attrib.get("offsetx") is not None:
        common.offset = OrderedPair(
            float(raw_layer.attrib["offsetx"]), float(raw_layer.attrib["offsety"])
        )

    properties_element = raw_layer.find("./properties")
    if properties_element is not None:
        common.properties = parse_properties(properties_element)

    parallax = [1.0, 1.0]

    if raw_layer.attrib.get("parallaxx") is not None:
        parallax[0] = float(raw_layer.attrib["parallaxx"])

    if raw_layer.attrib.get("parallaxy") is not None:
        parallax[1] = float(raw_layer.attrib["parallaxy"])

    common.parallax_factor = OrderedPair(parallax[0], parallax[1])

    if raw_layer.attrib.get("tintcolor") is not None:
        common.tint_color = parse_color(raw_layer.attrib["tintcolor"])

    return common


def _parse_tile_layer(raw_layer: etree.Element) -> TileLayer:
    """Parse the raw_layer to a TileLayer.

    Args:
        raw_layer: XML Element to be parsed to a TileLayer.

    Returns:
        TileLayer: The TileLayer created from raw_layer
    """
    common = _parse_common(raw_layer).__dict__
    del common["size"]
    tile_layer = TileLayer(
        size=Size(int(raw_layer.attrib["width"]), int(raw_layer.attrib["height"])),
        **common,
    )

    data_element = raw_layer.find("data")
    if data_element is not None:
        encoding = None
        if data_element.attrib.get("encoding") is not None:
            encoding = data_element.attrib["encoding"]

        compression = ""
        if data_element.attrib.get("compression") is not None:
            compression = data_element.attrib["compression"]

        raw_chunks = data_element.findall("chunk")
        if not raw_chunks:
            if encoding and encoding != "csv":
                tile_layer.data = _decode_tile_layer_data(
                    data=data_element.text,  # type: ignore
                    compression=compression,
                    layer_width=int(raw_layer.attrib["width"]),
                )
            else:
                tile_layer.data = _convert_raw_tile_layer_data(
                    [int(v.strip()) for v in data_element.text.split(",")],  # type: ignore
                    int(raw_layer.attrib["width"]),
                )
        else:
            chunks = []
            for raw_chunk in raw_chunks:
                chunks.append(
                    _parse_chunk(
                        raw_chunk,
                        encoding,
                        compression,
                    )
                )

            if chunks:
                tile_layer.chunks = chunks

    return tile_layer


def _parse_object_layer(
    raw_layer: etree.Element, parent_dir: Optional[Path] = None
) -> ObjectLayer:
    """Parse the raw_layer to an ObjectLayer.

    Args:
        raw_layer: XML Element to be parsed to an ObjectLayer.

    Returns:
        ObjectLayer: The ObjectLayer created from raw_layer
    """
    objects = []
    for object_ in raw_layer.findall("./object"):
        objects.append(parse_object(object_, parent_dir))

    object_layer = ObjectLayer(
        tiled_objects=objects,
        **_parse_common(raw_layer).__dict__,
    )

    if raw_layer.attrib.get("draworder") is not None:
        object_layer.draw_order = raw_layer.attrib["draworder"]

    return object_layer


def _parse_image_layer(raw_layer: etree.Element) -> ImageLayer:
    """Parse the raw_layer to an ImageLayer.

    Args:
        raw_layer: XML Element to be parsed to an ImageLayer.

    Returns:
        ImageLayer: The ImageLayer created from raw_layer
    """
    image_element = raw_layer.find("./image")
    if image_element is not None:
        source = Path(image_element.attrib["source"])

        transparent_color = None
        if image_element.attrib.get("trans") is not None:
            transparent_color = parse_color(image_element.attrib["trans"])

        image_layer = ImageLayer(
            image=source,
            transparent_color=transparent_color,
            **_parse_common(raw_layer).__dict__,
        )
        print(image_layer.size)
        return image_layer

    raise RuntimeError("Tried to parse an image layer that doesn't have an image!")


def _parse_group_layer(
    raw_layer: etree.Element, parent_dir: Optional[Path] = None
) -> LayerGroup:
    """Parse the raw_layer to a LayerGroup.

    Args:
        raw_layer: XML Element to be parsed to a LayerGroup.

    Returns:
        LayerGroup: The LayerGroup created from raw_layer
    """
    layers: List[Layer] = []
    for layer in raw_layer.findall("./layer"):
        layers.append(_parse_tile_layer(layer))

    for layer in raw_layer.findall("./objectgroup"):
        layers.append(_parse_object_layer(layer, parent_dir))

    for layer in raw_layer.findall("./imagelayer"):
        layers.append(_parse_image_layer(layer))

    for layer in raw_layer.findall("./group"):
        layers.append(_parse_group_layer(layer, parent_dir))
    # layers = []
    # layers = [
    #    parse(child_layer, parent_dir=parent_dir)
    #    for child_layer in raw_layer.iter()
    #    if child_layer.tag in ["layer", "objectgroup", "imagelayer", "group"]
    # ]

    return LayerGroup(layers=layers, **_parse_common(raw_layer).__dict__)


def parse(
    raw_layer: etree.Element,
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
    type_ = raw_layer.tag

    if type_ == "objectgroup":
        return _parse_object_layer(raw_layer, parent_dir)
    elif type_ == "group":
        return _parse_group_layer(raw_layer, parent_dir)
    elif type_ == "imagelayer":
        return _parse_image_layer(raw_layer)
    elif type_ == "layer":
        return _parse_tile_layer(raw_layer)

    raise RuntimeError(f"An invalid layer type of {type_} was supplied")
