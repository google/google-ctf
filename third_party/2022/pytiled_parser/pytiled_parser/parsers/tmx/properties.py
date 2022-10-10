import xml.etree.ElementTree as etree
from pathlib import Path
from typing import List, Union, cast

from pytiled_parser.properties import Properties, Property, ClassProperty, ObjectRefProperty
from pytiled_parser.util import parse_color


def parse(raw_properties: etree.Element) -> Properties:

    final: Properties = {}
    value: Property

    for raw_property in raw_properties.findall("property"):

        type_ = raw_property.attrib.get("type")
        if type_ == "class":
            children_nodes = raw_property.find("./properties")
            x = ClassProperty(
                raw_property.attrib["propertytype"], parse(children_nodes) if children_nodes is not None else {})
            final[raw_property.attrib["name"]] = x
            continue

        value_ = raw_property.attrib["value"]
        if type_ == "file":
            value = Path(value_)
        elif type_ == "color":
            value = parse_color(value_)
        elif type_ == "int" or type_ == "float":
            value = float(value_)
        elif type_ == "bool":
            if value_ == "true":
                value = True
            else:
                value = False
        elif type_ == "object":
            value = ObjectRefProperty(value_)
        else:
            value = value_
        final[raw_property.attrib["name"]] = value

    return final
