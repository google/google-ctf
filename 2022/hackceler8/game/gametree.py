# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import collections
import dataclasses

import numpy as np
import pytiled_parser

import environ
import serialize
import sprites
import utils
import copy
from typing import Union, Callable, Optional, Dict
import struct

component_types: Dict[str, type['Component']] = {}

@dataclasses.dataclass
class Frameset(serialize.SerializableObject):
    frameset: str
    flipped_horizontally: bool = False
    flipped_vertically: bool = False

class Vector(np.ndarray):
    def __new__(cls, dtype, size, unused_iterable=None):
        return np.ndarray.__new__(cls, shape=(size,), dtype=dtype, buffer=None, offset=0,
            strides=None, order=None)

    def __init__(self, unused_dtype=None, unused_size=None, iterable=None):
        if iterable is None:
            iterable = [0] * len(self)

        if len(iterable) != len(self):
            raise RuntimeError(f"Wrong length: got {len(iterable)} elements when trying to initialize {self.__class__.__name__}")
        for i in range(len(self)):
            self[i] = iterable[i]

    def __repr__(self):
        return "[" + ", ".join(str(x) for x in self) + "]"

    def __str__(self):
        return self.__repr__()
        return obj

    @classmethod
    def stringify(cls, stringifier, entity_id, entity) -> str:
        dtype, buf = entity.custom.split(b"\0", 1)
        vals = np.frombuffer(buf, dtype)
        return f"{stringifier.padding()}{vals}\n"

def Vector_serialize(obj: Vector, serializer, proto):
    proto.custom = obj.dtype.name.encode("utf-8") + b"\0" + obj.tobytes()

def Vector_deserialize(cls, deserializer, entity_id, entity):
    dtype, buf = entity.custom.split(b"\0", 1)
    vals = np.frombuffer(buf, dtype)

    obj = cls(dtype, vals)
    deserializer.add_to_cache(entity_id, obj)
    return obj

serialize.register_custom_serializer(Vector,
                                     Vector_serialize, Vector_deserialize)


class Vector2(Vector):
    def __new__(cls, dtype, *args, **kwargs):
        return Vector.__new__(cls, dtype, 2)

    def __init__(self, unused_dtype=None, *args, **kwargs):
        if len(args) != 0 and len(kwargs) != 0:
            raise RuntimeError("Either use positional or keyword args, not both.")

        if len(args) == 0 and len(kwargs) == 0:
            Vector.__init__(self, unused_dtype, 2)
        elif len(args) == 1:
            Vector.__init__(self, unused_dtype, 2, args[0])
        elif len(args) == 2:
            Vector.__init__(self, unused_dtype, 2, args)
        elif 'iterable' in kwargs:
            Vector.__init__(self, unused_dtype, 2, kwargs['iterable'])
        elif len(kwargs) != 0:
            Vector.__init__(self, unused_dtype, 2, (kwargs.get('x', 0), kwargs.get('y', 0)))
        else:
            raise RuntimeError(f"Got nonsensical arguments to Vector2: {args} {kwargs}")

    @property
    def x(self):
        return self[0]

    @x.setter
    def x(self, value):
        self[0] = value

    @property
    def y(self):
        return self[1]

    @y.setter
    def y(self, value):
        self[1] = value


serialize.register_custom_serializer(Vector2,
                                     Vector_serialize, Vector_deserialize)

class Vector3(Vector):
    def __new__(cls, dtype, *args, **kwargs):
        return Vector.__new__(cls, dtype, 3)

    def __init__(self, unused_dtype=None, *args, **kwargs):
        if len(args) != 0 and len(kwargs) != 0:
            raise RuntimeError("Either use positional or keyword args, not both.")

        if len(args) == 0 and len(kwargs) == 0:
            Vector.__init__(self, unused_dtype, 3)
        elif len(args) == 1:
            Vector.__init__(self, unused_dtype, 3, args[0])
        elif len(args) == 3:
            Vector.__init__(self, unused_dtype, 3, args)
        elif 'iterable' in kwargs:
            Vector.__init__(self, unused_dtype, 3, kwargs['iterable'])
        elif len(kwargs) != 0:
            Vector.__init__(self, unused_dtype, 3, (kwargs.get('x', 0), kwargs.get('y', 0), kwargs.get('z', 0)))
        else:
            raise RuntimeError(f"Got nonsensical arguments to Vector3: {args} {kwargs}")

    @property
    def x(self):
        return self[0]

    @x.setter
    def x(self, value):
        self[0] = value

    @property
    def y(self):
        return self[1]

    @y.setter
    def y(self, value):
        self[1] = value

    @property
    def z(self):
        return self[2]

    @z.setter
    def z(self, value):
        self[2] = value

serialize.register_custom_serializer(Vector3,
                                     Vector_serialize, Vector_deserialize)

def Vector2i(*args, **kwargs) -> Vector2:
    return Vector2(np.int64, *args, **kwargs)

def Vector2f(*args, **kwargs) -> Vector2:
    return Vector2(np.double, *args, **kwargs)

def Vector3i(*args, **kwargs) -> Vector3:
    return Vector3(np.int64, *args, **kwargs)

def Vector3f(*args, **kwargs) -> Vector3:
    return Vector3(np.double, *args, **kwargs)

class Transform:
    __slots__ = ["position", "rotation", "base_size", "size", "flip_x", "flip_y", "rotation_anchor"]
    def __init__(self, position=None, rotation=0.0, base_size=None, size=None, flip_x=False, flip_y=False,
                 rotation_anchor=None):
        super().__init__()
        self.position: Vector2 = position or Vector2f()
        self.rotation: float = rotation
        self.base_size: Vector2 = base_size or Vector2f()
        self.size: Vector2 = size or Vector2f(self.base_size.x, self.base_size.y)
        self.flip_x: bool = flip_x
        self.flip_y: bool = flip_y
        self.rotation_anchor: Vector2 = rotation_anchor or Vector2f()

    @property
    def x(self):
        return self.position.x

    @x.setter
    def x(self, value):
        self.position.x = value

    @property
    def y(self):
        return self.position.y

    @y.setter
    def y(self, value):
        self.position.y = value

    @environ.client_only
    def transform_sprite(self, sprite: sprites.Sprite):
        # We use bottom left coords, and to match Tiled we put (0, 0)
        # in the top-left of the map. Sprites use center-center coords, and put (0, 0) in the bottom
        # left with y pointing up.
        position = Vector2f(self.position)
        position.y = environ.game.map_size.y - position.y
        position.x += self.size.x / 2
        position.y += self.size.y / 2
        sprite.angle = -self.rotation
        sprite.width = self.size[0]
        sprite.height = self.size[1]
        sprite.set_texture(int(self.flip_x) + 2 * int(self.flip_y))

        # Calculate the offset needed for the rotation
        transformed_corner = utils.rotate_point(self.rotation_anchor * self.size, self.size / 2, -self.rotation)
        position -= transformed_corner
        position += self.rotation_anchor * self.size

        sprite.position = position

    def transform_point(self, point) -> Vector2:
        ret = Vector2f(x=point[0], y=point[1] - self.base_size.y)
        if self.flip_x:
            ret.x = self.base_size.x - ret.x
        if self.flip_y:
            ret.y = self.base_size.y - ret.y
        ret *= self.scale
        ret = utils.rotate_point(ret, self.rotation_anchor * self.size * Vector2f(1, -1), self.rotation)

        ret += self.position
        return ret

    def transform_points(self, points):
        if self.flip_x == self.flip_y:
            return type(points)(
                self.transform_point(point) for point in points
            )
        else:
            # We've flipped the shape, we need to invert point order
            return type(points)(
                reversed([self.transform_point(point) for point in points])
            )

    @environ.client_only
    def transform_point_to_pyarcade_space(self, point) -> Vector2:
        ret = self.transform_point(point)
        ret.y = environ.game.map_size.y - ret.y
        return ret

    @environ.client_only
    def transform_points_to_pyarcade_space(self, points):
        return type(points)(
            self.transform_point_to_pyarcade_space(point) for point in points
        )

    @property
    def scale(self) -> Vector2:
        if self.base_size.x == 0:
            raise RuntimeError("Failed to correctly configure size in transform")
        return self.size / self.base_size

    @scale.setter
    def scale(self, value):
        self.size = value * self.base_size

_transform_format = (
    "dd" # position
    "d" # rotation
    "dd" # base_size
    "dd" # size
    "?" # flip_x
    "?" # flip_y
    "dd" # rotation_anchor
)
def Transform_serialize(obj: Transform, serializer, proto):
    proto.custom = struct.pack(_transform_format,
                               obj.position.x, obj.position.y,
                               obj.rotation,
                               obj.base_size.x, obj.base_size.y,
                               obj.size.x, obj.size.y,
                               obj.flip_x,
                               obj.flip_y,
                               obj.rotation_anchor.x, obj.rotation_anchor.y)

def Transform_deserialize(typ, deserializer, entity_id, o):
    obj = typ()
    (
        obj.position.x, obj.position.y,
        obj.rotation,
        obj.base_size.x, obj.base_size.y,
        obj.size.x, obj.size.y,
        obj.flip_x,
        obj.flip_y,
        obj.rotation_anchor.x, obj.rotation_anchor.y
    ) = struct.unpack(_transform_format, o.custom)
    return obj

serialize.register_custom_serializer(Transform,
    Transform_serialize, Transform_deserialize)


class Entity(serialize.SerializableObject):
    _components_by_type = serialize.Unserialized()
    _children_by_name = serialize.Unserialized()
    _transform_modified = serialize.Unserialized()

    def __init__(self, name="Entity", transform=None):
        super().__init__()
        self._name: str = name
        self._transform: Transform = transform or Transform()
        self._components = []
        self._components_by_type = {}
        self._children = []
        self._children_by_name = {}
        self._parent = None
        self.tmx_data = None
        self.id: int = -1
        self._frameset: str = ""
        self._transform_modified: list[int] = [environ.game.get_modification_stamp()]

    def _add_component_to_type_table(self, component, base):
        self._components_by_type.setdefault(base.__name__, list()).append(component)
        for b in base.__bases__:
            self._add_component_to_type_table(component, b)

    def add_component(self, component):
        if component.entity:
            raise RuntimeError(f"Each Component can be a member of only one Entity. Attempted to add {component} to entity {self}.")
        self._components.append(component)
        self._add_component_to_type_table(component, type(component))

        component._entity = self
        component.added()
        if component.additional_framesets:
            for component in self._components:
                component.on_framesets_changed(self.framesets, environ.game)
        elif self.framesets:
            component.on_framesets_changed(self.framesets, environ.game)

        if self.framesets:
            initial_frameset = environ.game.get_tile(component.entity.gid).properties["frameset"]
            component.on_frameset_changed(initial_frameset)

        return component

    def _remove_component_from_type_table(self, component, base):
        self._components_by_type[base.__name__].remove(component)
        for b in base.__bases__:
            self._remove_component_from_type_table(component, b)

    def remove_component(self, component):
        if component.entity != self:
            raise RuntimeError(f"Attempted to remove component {component} from entity {self} that is not its parent. Actual parent: {component.entity}")
        component.removed()
        self._components.remove(component)
        self._remove_component_from_type_table(component, type(component))
        component._entity = None

        if component.additional_framesets:
            for component in self._components:
                component.on_framesets_changed(self.framesets, environ.game)

        return component

    def get_component(self, cls):
        """Gets the component of the specified type."""
        if cls.__name__ not in self._components_by_type:
            return None
        l = self._components_by_type[cls.__name__]
        if len(l) == 0:
            return None
        return l[0]

    def get_component_in_children(self, cls):
        """Gets the component of the specified type from this object or its desendants."""
        ret = self.get_component(cls)
        if ret is not None:
            return ret
        for child in self._children:
            ret = child.get_component_in_children(cls)
            if ret is not None:
                return ret
        return None

    def get_components(self, cls):
        """Gets the component of the specified type."""
        if cls.__name__ not in self._components_by_type:
            return tuple()
        return tuple(self._components_by_type[cls.__name__])

    def get_components_in_children(self, cls) -> list:
        """Gets all components of the specified type from this object or its desendants."""
        ret = []
        c = self.get_component(cls)
        if c is not None:
            ret.append(c)
        for child in self._children:
            ret += child.get_components_in_children(cls)
        return ret

    @property
    def components(self) -> tuple:
        return tuple(self._components)


    def add_child(self, child: "Entity"):
        if child._parent is not None:
            raise RuntimeError(f"Attempted to add Entity {child} which already has parent {child._parent} as a child of {self}.")
        self._children.append(child)
        self._children_by_name.setdefault(child.name, list()).append(child)
        child._parent = self
        return child

    def remove_child(self, child: "Entity"):
        if child._parent != self:
            raise RuntimeError(f"Attempted to remove child entity {child} from parent entity {self} which is not its parent; actual parent is {child._parent}.")

        self._children.remove(child)
        self._children_by_name[child.name].remove(child)
        child._parent = None
        child.dispatch_to_components("entity_removed", self)
        return child

    def get_child(self, name: str):
        if name not in self._children_by_name:
            return None
        l = self._children_by_name[name]
        if len(l) == 0:
            return None
        return l[0]

    def get_child_r(self, name: str):
        ret = self.get_child(name)
        if ret is not None:
            return ret
        for child in self._children:
            ret = child.get_child_r(name)
            if ret is not None:
                return ret
        return None

    def get_children(self, name: str):
        if name not in self._children_by_name:
            return tuple()
        return tuple(self._children_by_name[name])

    def dispatch_to_components(self, func_or_func_name: Union[Callable, str], *args, **kwargs):
        if isinstance(func_or_func_name, str):
            return self._dispatch_to_components_str(func_or_func_name, *args, **kwargs)
        else:
            return self._dispatch_to_components_func(func_or_func_name, *args, **kwargs)

    def _dispatch_to_components_func(self, func: Callable, *args, **kwargs):
        for component in self._components:
            val = func(component, *args, **kwargs)
            if val:
                return val

    def _dispatch_to_components_str(self, func_name: str, *args, **kwargs):
        for component in self._components:
            try:
                func = getattr(component, func_name)
            except AttributeError:
                continue
            val = func(*args, **kwargs)
            if val:
                return val


    def dispatch_to_tree(self, func_or_func_name: Union[Callable, str], *args, **kwargs):
        if isinstance(func_or_func_name, str):
            return self._dispatch_to_tree_str(func_or_func_name, *args, **kwargs)
        else:
            return self._dispatch_to_tree_func(func_or_func_name, *args, **kwargs)

    def _dispatch_to_tree_func(self, func: Callable, *args, **kwargs):
        val = self._dispatch_to_components_func(func, *args, **kwargs)
        if val:
            return val
        for child in self._children:
            val = child._dispatch_to_tree_func(func, *args, **kwargs)
            if val:
                return val

    def _dispatch_to_tree_str(self, func_name: str, *args, **kwargs):
        val = self._dispatch_to_components_str(func_name, *args, **kwargs)
        if val:
            return val
        for child in self._children:
            val = child._dispatch_to_tree_str(func_name, *args, **kwargs)
            if val:
                return val

    def find_by_id(self, id: int):
        """Find an object by its id."""
        if self.id == id:
            return self
        for child in self._children:
            ret = child.find_by_id(id)
            if ret is not None:
                return ret
        return None

    def find_by_name(self, name: str):
        """Find an object by its name."""
        if self.name == name:
            return self
        for child in self._children:
            ret = child.find_by_name(name)
            if ret is not None:
                return ret
        return None

    @property
    def transform(self):
        #return self._transform
        return utils.ModifiedProxy(self._transform, self._transform_modified)

    @transform.setter
    def transform(self, value):
        if isinstance(value, utils.Proxy):
            self._transform = copy.deepcopy(value._wrapped)
        else:
            self._transform = value
        self._transform_modified[0] = environ.game.get_modification_stamp()

    @property
    def children(self) -> tuple:
        return tuple(self._children)

    @property
    def parent(self):
        return self._parent

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, value):
        if self._parent is not None:
            self._parent._children_by_name.setdefault(self._name, list()).remove(self)
            self._parent._children_by_name.setdefault(value, list()).append(self)
        self._name = value

    def init_unserialized(self, deserializer):
        super().init_unserialized(deserializer)

        self._components_by_type = {}
        self._children_by_name = {}
        self._transform_modified = [0]

        for component in self._components:
            self._add_component_to_type_table(component, type(component))
        for child in self._children:
            self._children_by_name.setdefault(child.name, list()).append(child)

    def post_deserialize(self, deserializer):
        for component in self._components:
            component.on_framesets_changed(self.framesets, deserializer.context)
            component.on_frameset_changed(self.frameset)

    @environ.client_only
    def draw(self):
        for component in self._components:
            ret = component.draw()
            if ret:
                return
        for child in self._children:
            ret = child.draw()
            if ret:
                return
        return False

    @property
    def framesets(self) -> dict[str, Frameset]:
        ret = {}
        for component in self._components:
            if component.additional_framesets:
                ret.update(component.additional_framesets)
        return ret

    @property
    def frameset(self) -> str:
        return self._frameset

    @frameset.setter
    def frameset(self, frameset: str):
        self._frameset = frameset
        for component in self._components:
            component.on_frameset_changed(frameset)

    @property
    def original_frameset(self) -> Optional[set]:
        return self.tmx_data.properties.get('frameset', None)

    @property
    def transform_modified(self):
        return self._transform_modified[0]

    @property
    def renderer(self):
        import renderer as renderer_mod
        for component in self._components:
            if isinstance(component, renderer_mod.Renderer):
                return component
        return None

    @property
    def sprite(self):
        return self.renderer.sprite

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name

    def duplicate(self, name, id=-1):
        if self._children:
            raise NotImplementedError("The ability to duplicate entities with children is not yet implemented.")

        new_entity = self.__class__(name=name)
        new_entity.transform = self.transform

        new_entity.tmx_data = self.tmx_data
        new_entity.id = id
        new_entity.gid = self.gid
        new_entity._frameset = self._frameset

        for component in self._components:
            c = component.duplicate(new_entity)
            new_entity.add_component(c)

        new_entity.frameset = self.frameset

        return new_entity


class Component(serialize.SerializableObject):
    additional_framesets = environ.pick(client={}, server=None)

    def __init__(self):
        super().__init__()
        self._entity: Optional[Entity] = None

    def __init_subclass__(cls):
        super().__init_subclass__()
        name = cls.__name__
        if name in component_types:
            already = component_types[name]
            raise RuntimeError(f"Cannot create entity named '{name}': name already registered to class '{already}'.")
        component_types[name] = cls

    def added(self):
        """Called right after this component is added to its entity."""

    def tick(self):
        """Called every tick."""
        pass

    def removed(self):
        """Called right before this component is removed from its entity."""
        pass

    @property
    def entity(self) -> Optional[Entity]:
        # hasattr() on a __getattr__ object is really slow. It produces a meaningful speedup to bypass it here.
        return self._ensure_state_fields().get("_entity", None)

    @property
    def transform(self) -> utils.ModifiedProxy:
        return self.entity.transform

    @transform.setter
    def transform(self, value):
        self.entity.transform = value

    @environ.client_only
    def draw(self):
        pass

    def on_frameset_changed(self, frameset):
        pass

    def on_framesets_changed(self, framesets, game):
        pass

    def duplicate(self, new_entity):
        raise NotImplementedError(f"Component {self.__class__} does not implement `duplicate(self, new_entity)`.")
