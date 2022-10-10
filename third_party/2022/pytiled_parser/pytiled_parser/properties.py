"""Properties Module

This module defines types for Property objects.
For more about properties in Tiled maps see the below link:
https://doc.mapeditor.org/en/stable/manual/custom-properties/

The types defined in this module get added to other objects
such as Layers, Maps, Objects, etc
"""

from pathlib import Path
from typing import Dict, Union

from .common_types import Color

class ClassProperty(dict):
	def __init__(self, propertytype:str, *args, **kwargs):
		self.propertytype = propertytype or ''
		dict.__init__(self, *args, **kwargs)

class ObjectRefProperty(str):
	pass

Property = Union[float, Path, str, bool, Color, ClassProperty, ObjectRefProperty]

Properties = Dict[str, Property]
