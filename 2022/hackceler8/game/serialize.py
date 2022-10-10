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

import json
import math
import sys
from array import array
from collections import deque
from typing import Type, Any, Optional, Callable, Iterable, Protocol

import serialization_pb2
import utils


def IsSerializable(obj) -> bool:
    if isinstance(obj, SerializableBase):
        return True
    elif isinstance(obj, str):
        return True
    elif isinstance(obj, bytes):
        return True
    elif isinstance(obj, int):
        return True
    elif isinstance(obj, float):
        return True
    elif isinstance(obj, bool):
        return True
    elif isinstance(obj, array):
        return True
    elif obj is None:
        return True

    name = type_name(type(obj))
    if name in _custom_serializable_object_registry:
        return True

    return False


def IsSerializeConvertible(obj) -> bool:
    if isinstance(obj, list):
        return True
    elif isinstance(obj, deque):
        return True
    elif isinstance(obj, set):
        return True
    elif isinstance(obj, dict):
        return True
    elif isinstance(obj, tuple):
        return True
    return False


def SerializeConvert(arg):
    if arg.__class__ == list:
        return SerializableList(arg)
    elif arg.__class__ == deque:
        return SerializableDeque(arg)
    elif arg.__class__ == set:
        return SerializableSet(arg)
    elif arg.__class__ == dict:
        return SerializableDict(arg)
    elif arg.__class__ == tuple:
        return SerializableTuple(arg)
    return arg

class SerializableBase(object):
    pass

_serializable_object_registry: dict = {}
_custom_serializable_object_registry: dict[str, tuple] = {}

def type_name(cls) -> str:
    return cls.__module__ + "." + cls.__name__

def register_custom_serializer(cls, serializer, deserializer, stringifier=None):
    name = type_name(cls)
    if name in _serializable_object_registry:
        already = _serializable_object_registry[name][0]
        raise RuntimeError(f"Cannot register custom serializer for class '{name}': name already registered to class '{already}'.")
    _custom_serializable_object_registry[name] = (cls, serializer, deserializer, stringifier)


class SerializableObject(SerializableBase):
    def __init__(self):
        self._ensure_state_fields()

    def __init_subclass__(cls):
        name = type_name(cls)
        if name in _serializable_object_registry:
            already = _serializable_object_registry[name]
            raise RuntimeError(f"Cannot create serializable class named '{name}': name already registered to class '{already}'.")
        _serializable_object_registry[name] = cls

    def __new__(cls, *args, **kwargs):
        self = SerializableBase.__new__(cls)
        for name, field in cls.__dict__.items():
            if isinstance(field, _Unserialized):
                self.__dict__[name] = field.value

        return self


    def _ensure_state_fields(self):
        try:
            return object.__getattribute__(self, "_state_fields")
        except AttributeError:
            state_fields = {}
            object.__setattr__(self, "_state_fields", state_fields)
            return state_fields

    def __setattr__(self, name: str, value):
        # Real fields aren't serialized. (This applies to functions and things like __class__)
        if name == "type_name" or name == "__type__":
            raise RuntimeError(f"Cannot set reserved field '{name}'.")

        if isinstance(value, _Unserialized):
            object.__setattr__(self, name, value.value)
            return

        if name in dir(self):
            object.__setattr__(self, name, value)
            return

        if IsSerializeConvertible(value):
            value = SerializeConvert(value)

        if not IsSerializable(value):
            sys.stderr.write(f"Type {self.__class__.__name__} is serializable - cannot add non-serializable field of type {value.__class__.__name__}.\n")
            raise RuntimeError(f"Type {self.__class__.__name__} is serializable - cannot add non-serializable field of type {value.__class__.__name__}.")

        self._ensure_state_fields()
        self._state_fields[name] = value

    def __getattr__(self, name: str):
        self._ensure_state_fields()

        if name in self._state_fields:
            return self._state_fields[name]
        raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")

    def deserialize_state_fields(self, deserializer, entity_id, entity):
        self._ensure_state_fields()
        self._state_fields = deserializer._deserialize_dict_impl({}, entity.fields)

    @classmethod
    def deserialize(cls, deserializer, entity_id, entity):
        obj = cls.__new__(cls)
        deserializer.add_to_cache(entity_id, obj)
        obj.deserialize_state_fields(deserializer, entity_id, entity)
        obj.init_unserialized(deserializer)
        return obj

    def serialize(self, serializer, proto):
        proto.type = type_name(type(self))
        self._ensure_state_fields()
        for k, v in self._state_fields.items():
            pair = proto.fields.entries.add()
            pair.key = serializer.serialize_entity(k)
            pair.val = serializer.serialize_entity(v)

    def init_unserialized(self, deserializer):
        pass

    def post_deserialize(self, deserializer):
        pass


class SerializableList(list, SerializableBase):
    def __init__(self, *args, **kwargs):
        list.__init__(self, *args, **kwargs)
        for i in range(len(self)):
            item = SerializeConvert(self[i])
            list.__setitem__(self, i, item)
            if not IsSerializable(item):
                raise RuntimeError(f"Cannot add non-serializable object '{item}' of type '{item.__class__.__name__}' to serializable list.")

    def _ProcessValue(self, value):
        if IsSerializeConvertible(value):
            return SerializeConvert(value)

        if not IsSerializable(value):
            raise RuntimeError(f"Cannot add non-serializable object '{value}' of type '{value.__class__.__name__}' to serializable list.")
        return value

    def __setitem__(self, name, value):
        value = self._ProcessValue(value)
        return list.__setitem__(self, name, value)

    def append(self, value):
        value = self._ProcessValue(value)
        return list.append(self, value)

    def extend(self, iterable: Iterable):
        added = 0
        try:
            for x in iterable:
                x = self._ProcessValue(x)
                list.append(self, x)
                added += 1
        except RuntimeError:
            while added > 0:
                list.pop(self)
                added -= 1
            raise

    def insert(self, i, value):
        value = self._ProcessValue(value)
        return list.insert(self, i, value)


class SerializableTuple(tuple, SerializableBase):
    # Tuple's members are set in __new__, not in __init__.
    def __new__(cls, iterable=None):
        if iterable is None:
            return tuple.__new__(cls)

        tmp = []
        for i in iterable:
            item = SerializeConvert(i)
            if not IsSerializable(item):
                raise RuntimeError(f"Cannot add non-serializable object '{item}' of type '{item.__class__.__name__}' to serializable tuple.")
            tmp.append(item)
        return tuple.__new__(cls, tmp)


class SerializableDeque(deque, SerializableBase):
    def __init__(self, *args, **kwargs):
        deque.__init__(self, *args, **kwargs)
        for i in range(len(self)):
            item = SerializeConvert(self[i])
            deque.__setitem__(self, i, item)
            if not IsSerializable(item):
                raise RuntimeError(f"Cannot add non-serializable object '{item}' of type '{item.__class__.__name__}' to serializable deque.")

    def _ProcessValue(self, value):
        if IsSerializeConvertible(value):
            return SerializeConvert(value)

        if not IsSerializable(value):
            raise RuntimeError(f"Cannot add non-serializable object '{value}' of type '{value.__class__.__name__}' to serializable deque.")
        return value

    def __setitem__(self, name, value):
        value = self._ProcessValue(value)
        return deque.__setitem__(self, name, value)

    def append(self, value):
        value = self._ProcessValue(value)
        return deque.append(self, value)

    def appendLeft(self, value):
        value = self._ProcessValue(value)
        return deque.append(self, value)

    def extend(self, iterable: Iterable):
        added = 0
        try:
            for x in iterable:
                x = self._ProcessValue(x)
                deque.append(self, x)
                added += 1
        except RuntimeError:
            while added > 0:
                deque.pop(self)
                added -= 1
            raise

    def extendleft(self, iterable):
        added = 0
        try:
            for x in iterable:
                x = self._ProcessValue(x)
                deque.appendleft(self, x)
                added += 1
        except RuntimeError:
            while added > 0:
                deque.pop(self)
                added -= 1
            raise

    def insert(self, i, value):
        value = self._ProcessValue(value)
        return deque.insert(self, i, value)


# wrapped in a -> Any function to make mypy shut up
def Unserialized(x: Any = None) -> Any:
    return _Unserialized(x)


class _Unserialized(object):
    """Annotate a field as not to be included in serialization.

    Should typically be used as a class field. Instance vars of the
    same name won't be serialized.
    Example:
      class Foo(SerializableObject):
        my_unserialized_field = Unserialized()
      def __init__(self, foo):
        self.my_unserialized_field = "x"  # Will not be serialized
    """
    def __init__(self, arg=None):
        self.value = arg

    def __bool__(self):
        return self.value.__bool__()


class SerializableDict(dict, SerializableBase):
    def __init__(self, *args, **kwargs):
        dict.__init__(self, *args, **kwargs)
        kvs = [(k, v) for k, v in self.items()]
        self.clear()
        for k, item in kvs:
            if IsSerializeConvertible(k):
                k = SerializeConvert(k)
            if IsSerializeConvertible(item):
                item = SerializeConvert(item)
            dict.__setitem__(self, k, item)
            if not IsSerializable(k):
                raise RuntimeError(f"Cannot add non-serializable key '{item}' of type '{item.__class__.__name__}' to serializable dict.")
            if not IsSerializable(item):
                raise RuntimeError(f"Cannot add non-serializable object '{item}' of type '{item.__class__.__name__}' to serializable dict.")

    def _ProcessValue(self, value):
        if IsSerializeConvertible(value):
            return SerializeConvert(value)

        if not IsSerializable(value):
            raise RuntimeError(f"Cannot add non-serializable object '{value}' of type '{value.__class__.__name__}' to serializable dict.")

        return value

    def __setitem__(self, key, value):
        key = self._ProcessValue(key)
        value = self._ProcessValue(value)
        return dict.__setitem__(self, key, value)

    def setdefault(self, key, default=None):
        key = self._ProcessValue(key)
        if key in self:
            return self[key]

        default = self._ProcessValue(default)
        return dict.setdefault(self, key, default)

    def update(self, *args, **kwargs):
        if kwargs:
            other = kwargs
        elif len(args) > 0:
            other = args[0]
        else:
            return dict.update(self, *args, **kwargs)

        for k, v in other.items():
            dict[self._ProcessValue(k)] = self._ProcessValue(v)


class SerializableSet(set, SerializableBase):
    def __init__(self, *args, **kwargs):
        set.__init__(self, *args, **kwargs)
        elements = [k for k in self]
        self.clear()
        for k in elements:
            self.add(k)


    def _ProcessValue(self, value):
        if IsSerializeConvertible(value):
            return SerializeConvert(value)

        if not IsSerializable(value):
            raise RuntimeError(f"Cannot add non-serializable object '{value}' of type '{value.__class__.__name__}' to serializable set.")

        return value

    def add(self, key):
        set.add(self, self._ProcessValue(key))

    def update(self, *args):
        tmp = set()
        tmp.update(*args)
        tmp_serializable = Serializable(tmp)
        set.update(self, tmp_serializable)


class Serializer:
    def __init__(self, root):
        self.result = serialization_pb2.SerializedPackage()
        self.current_value = 1
        # Maps from id() -> shared value
        self.object_mapping = {}
        if isinstance(root, utils.ModifiedProxy):
            root = root.__dict__['_wrapped']
        self.root = self.serialize_entity(root)
        self.result.root_value = self.root

    def serialize_entity(self, obj):
        # add local object mapping to global mapping
        if id(obj) not in self.object_mapping:
            self.object_mapping[id(obj)] = self.current_value
            self.current_value += 1

        ret = self._serialize_entity(obj)
        if str(self.result.values[ret]) == "":
            raise RuntimeError(f"Serialization produced empty entity. Source: {obj}")
        return ret

    def _serialize_entity(self, obj):
        if self.object_mapping[id(obj)] in self.result.values:
            return self.object_mapping[id(obj)]

        if type(obj) == str:
            return self._serialize_str(obj)

        if type(obj) == bytes:
            return self._serialize_bytes(obj)

        if type(obj) == int:
            return self._serialize_int(obj)

        if type(obj) == float:
            return self._serialize_float(obj)

        if type(obj) == bool:
            return self._serialize_bool(obj)

        if obj is None:
            return self._serialize_none()

        if isinstance(obj, SerializableDict):
            return self._serialize_dict(obj)

        if isinstance(obj, SerializableList):
            return self._serialize_list(obj)

        if isinstance(obj, SerializableSet):
            return self._serialize_set(obj)

        if isinstance(obj, SerializableTuple):
            return self._serialize_tuple(obj)

        if isinstance(obj, SerializableDeque):
            return self._serialize_deque(obj)

        if isinstance(obj, array):
            return self._serialize_array(obj)

        if isinstance(obj, SerializableObject):
            return self._serialize_object(obj)

        name = type_name(type(obj))
        if name in _custom_serializable_object_registry:
            return self._custom_serialize_object(obj)

        # Fallback. These serializations happen only if the user has
        # bypassed serialization protections with custom serializers,
        # or if there's a bug in serialization.

        if isinstance(obj, dict):
            return self._serialize_dict(obj)

        if isinstance(obj, list):
            return self._serialize_list(obj)

        if isinstance(obj, set):
            return self._serialize_set(obj)

        if isinstance(obj, tuple):
            return self._serialize_tuple(obj)

        if isinstance(obj, deque):
            return self._serialize_deque(obj)

        raise RuntimeError(f"Unknown type to serialize: {obj.__class__} ({obj})")

    def _serialize_list(self, l: list):
        value = self.result.values[self.object_mapping[id(l)]]
        proto = value.list_val
        proto.SetInParent()
        for val in l:
            proto.fields.append(self.serialize_entity(val))
        return self.object_mapping[id(l)]

    def _serialize_set(self, l: set):
        value = self.result.values[self.object_mapping[id(l)]]
        proto = value.set_val
        proto.SetInParent()
        for val in l:
            proto.fields.append(self.serialize_entity(val))
        return self.object_mapping[id(l)]

    def _serialize_deque(self, d: deque):
        value = self.result.values[self.object_mapping[id(d)]]
        proto = value.deque_val
        proto.SetInParent()
        for val in d:
            proto.fields.append(self.serialize_entity(val))
        return self.object_mapping[id(d)]

    def _serialize_dict(self, d: dict):
        value = self.result.values[self.object_mapping[id(d)]]
        proto = value.dict_val
        proto.SetInParent()
        for k, v in d.items():
            pair = proto.entries.add()
            pair.key = self.serialize_entity(k)
            pair.val = self.serialize_entity(v)
        return self.object_mapping[id(d)]

    def _serialize_tuple(self, t: tuple):
        value = self.result.values[self.object_mapping[id(t)]]
        proto = value.tuple_val
        proto.SetInParent()
        for val in t:
            proto.fields.append(self.serialize_entity(val))
        return self.object_mapping[id(t)]

    def _serialize_object(self, obj: SerializableObject):
        value = self.result.values[self.object_mapping[id(obj)]]
        proto = value.object_val
        proto.type = type_name(type(obj))
        obj.serialize(self, proto)
        return self.object_mapping[id(obj)]

    def _custom_serialize_object(self, obj: object):
        value = self.result.values[self.object_mapping[id(obj)]]
        proto = value.object_val

        name = type_name(type(obj))
        proto.type = name
        _, serializer, _, _ = _custom_serializable_object_registry[name]

        serializer(obj, self, proto)

        return self.object_mapping[id(obj)]

    def _serialize_str(self, x: str):
        value = self.result.values[self.object_mapping[id(x)]]
        value.str_val = x
        return self.object_mapping[id(x)]

    def _serialize_bytes(self, x: bytes):
        value = self.result.values[self.object_mapping[id(x)]]
        value.bytes_val = x
        return self.object_mapping[id(x)]

    def _serialize_float(self, x: float):
        value = self.result.values[self.object_mapping[id(x)]]
        value.float_val = x
        return self.object_mapping[id(x)]

    def _serialize_bool(self, x: bool):
        value = self.result.values[self.object_mapping[id(x)]]
        value.bool_val = x
        return self.object_mapping[id(x)]

    def _serialize_int(self, x: int):
        value = self.result.values[self.object_mapping[id(x)]]
        if (x.bit_length() <= 63):
            value.int_val = x
        else:
            value.bigint_val = utils.serialize_int(x)
        return self.object_mapping[id(x)]

    def _serialize_array(self, x):
        value = self.result.values[self.object_mapping[id(x)]]
        value.array_val.typecode = ord(x.typecode)
        value.array_val.data = x.tobytes()
        return self.object_mapping[id(x)]

    def _serialize_none(self):
        value = self.result.values[0]
        value.nonetype_flag = True
        return 0


class Deserializer:
    def __init__(self, package, context=None):
        self.package = package
        self.context = context
        self._cache = {}
        self._expecting_cache = None
        self._poisoned_entities = set()
        self.result = self.deserialize_entity(package.root_value)
        self.call_post_deserialize()

    def call_post_deserialize(self):
        for val in self._cache.values():
            if hasattr(val, "post_deserialize"):
                val.post_deserialize(self)

    def deserialize_entity(self, entity_id):
        if self._expecting_cache is not None:
            raise RuntimeError("To prevent infinite loops, your deserialize() "
                "handler must instantiate its return object and call "
                "deserializer.add_to_cache(entity_id, obj) prior to any "
                "calls to deserializer.deserialize_entity(). Your return "
                "object does not need to be fully initialized, but it must have "
                "at least been been __new__()ed. "
                "if this is not possible, you can call deserializer.poison(entity_id) "
                "instead. This will allow you to recursively call "
                "deserializer.deserialize_entity(); however, if your object is part "
                "of any loops in the object graph, an exception will be raised "
                "on deserialization. "
                "Offending object: " +
                f"entity_id={self._expecting_cache}")
        if entity_id in self._cache:
            return self._cache[entity_id]
        self._expecting_cache = entity_id
        if entity_id in self._poisoned_entities:
            raise RuntimeError("Prohibited loop detected when deserializing entity "
                + f"{entity_id}")
        entity = self.package.values[entity_id]

        if entity.HasField("list_val"):
            return self._deserialize_list(entity_id, entity.list_val)

        if entity.HasField("set_val"):
            return self._deserialize_set(entity_id, entity.set_val)

        if entity.HasField("deque_val"):
            return self._deserialize_deque(entity_id, entity.deque_val)

        if entity.HasField("dict_val"):
            return self._deserialize_dict(entity_id, entity.dict_val)

        if entity.HasField("tuple_val"):
            return self._deserialize_tuple(entity_id, entity.tuple_val)

        if entity.HasField("object_val"):
            ret = self._deserialize_object(entity_id, entity.object_val)
            if entity_id not in self._cache:
                self.add_to_cache(entity_id, ret)
            return ret

        ret = self._deserialize_base_entity(entity)
        self.add_to_cache(entity_id, ret)
        return ret


    def _deserialize_base_entity(self, entity):
        ret = None
        if entity.HasField("int_val"):
            ret = entity.int_val

        elif entity.HasField("bigint_val"):
            ret = self._deserialize_bigint(entity.bigint_val)

        elif entity.HasField("float_val"):
            ret = entity.float_val

        elif entity.HasField("str_val"):
            ret = entity.str_val

        elif entity.HasField("bytes_val"):
            ret = entity.bytes_val

        elif entity.HasField("bool_val"):
            ret = entity.bool_val

        elif entity.HasField("array_val"):
            ret = self._deserialize_array(entity.array_val)

        elif entity.HasField("nonetype_flag"):
            ret = None

        else:
            raise RuntimeError(f"Got invalid entity {entity}")

        return ret

    def _deserialize_bigint(self, blob):
        return utils.deserialize_int(blob)

    def _deserialize_array(self, arr):
        ret = array(chr(arr.typecode))
        ret.frombytes(arr.data)
        return ret

    def add_to_cache(self, entity_id, obj):
        if entity_id in self._cache:
            raise Exception(f"Entity {entity_id} already present in cache.")
        if entity_id != self._expecting_cache and entity_id not in self._poisoned_entities:
            raise RuntimeError(
                "add_to_cache() should be called while deserializing the object it is called on. "
                + f"Called on {entity_id}, expecting {self._expecting_cache}.")

        self._expecting_cache = None
        self._cache[entity_id] = obj
        self._poisoned_entities.discard(entity_id)

    def poison(self, entity_id):
        if entity_id != self._expecting_cache:
            raise RuntimeError(
                "poison() should be called while deserializing the object it is called on. "
                + f"Called on {entity_id}, expecting {self._expecting_cache}.")
        self._poisoned_entities.add(entity_id)
        self._expecting_cache = None

    def _deserialize_list(self, entity_id, l) -> SerializableList:
        ret = SerializableList()
        self.add_to_cache(entity_id, ret)
        for i in l.fields:
            ret.append(self.deserialize_entity(i))
        return ret

    def _deserialize_set(self, entity_id, l) -> SerializableSet:
        ret = SerializableSet()
        self.add_to_cache(entity_id, ret)
        for i in l.fields:
            ret.add(self.deserialize_entity(i))
        return ret

    def _deserialize_deque(self, entity_id, d) -> SerializableDeque:
        ret = SerializableDeque()
        self.add_to_cache(entity_id, ret)
        for i in d.fields:
            ret.append(self.deserialize_entity(i))
        return ret

    def _deserialize_dict(self, entity_id, d) -> SerializableDict:
        ret = SerializableDict()
        self.add_to_cache(entity_id, ret)
        return self._deserialize_dict_impl(ret, d)

    def _deserialize_dict_impl(self, out, d):
        for entry in d.entries:
            key = self.deserialize_entity(entry.key)
            val = self.deserialize_entity(entry.val)
            out[key] = val
        return out

    def _deserialize_tuple(self, entity_id, t) -> SerializableTuple:
        self.poison(entity_id)
        ret = SerializableTuple(self.deserialize_entity(f) for f in t.fields)
        self.add_to_cache(entity_id, ret)
        return ret

    def _deserialize_object(self, entity_id, o):
        if o.type in _serializable_object_registry:
            typ = _serializable_object_registry[o.type]
            ret = typ.deserialize(self, entity_id, o)
        elif o.type in _custom_serializable_object_registry:
            typ, _, deserializer, _ = _custom_serializable_object_registry[o.type]
            ret = deserializer(typ, self, entity_id, o)
        else:
            raise RuntimeError(f"Attempt to deserialize unknown entity type {o.type}: {o}")
        if ret is None:

            raise RuntimeError(f"Deserializing entity {o} produced None.")
        for field in dir(ret):
            try:
                val = getattr(ret, field)
            except Exception:
                continue
            if isinstance(val, _Unserialized):
                sys.stderr.write(f"WARNING: Unserialized field {field} was not initialized on object {entity_id} {ret} by deserialize() or init_unserialized(). You probably need to implement init_unserialized().\n")
        return ret


def Serialize(obj) -> serialization_pb2.SerializedPackage:
    return Serializer(obj).result


def Deserialize(obj, context=None):
    return Deserializer(obj, context).result


def simple_custom_serializer(obj, serializer, proto):
    for k, v in obj.__dict__.items():
        pair = proto.fields.entries.add()
        pair.key = serializer.serialize_entity(k)
        pair.val = serializer.serialize_entity(v)


def simple_custom_deserializer(typ, deserializer, entity_id, o):
    ret = typ.__new__(typ)
    deserializer.add_to_cache(entity_id, ret)
    for entry in o.fields.entries:
        key = deserializer.deserialize_entity(entry.key)
        val = deserializer.deserialize_entity(entry.val)
        setattr(ret, key, val)
    return ret


def namedtuple_custom_serializer(obj, serializer, proto):
    for k, v in obj._asdict().items():
        pair = proto.fields.entries.add()
        pair.key = serializer.serialize_entity(k)
        pair.val = serializer.serialize_entity(v)


def namedtuple_custom_deserializer(typ, deserializer, entity_id, o):
    deserializer.poison(entity_id)
    vals = {}
    for entry in o.fields.entries:
        key = deserializer.deserialize_entity(entry.key)
        val = deserializer.deserialize_entity(entry.val)
        vals[key] = val
    ret = typ(**vals)
    deserializer.add_to_cache(entity_id, ret)
    return ret


class _Stringifier:
    def __init__(self, serialized: serialization_pb2.SerializedPackage):
        self.serialized = serialized
        self.seen: set[str] = set()
        self.indent = 0

    def stringify(self) -> str:
        return self._stringify(self.serialized.root_value)

    def _stringify(self, id: str) -> str:
        obj = self.serialized.values[id]
        if obj.HasField('int_val'):
            return f"{self.padding()}{obj.int_val}\n"
        if obj.HasField('bigint_val'):
            return f"{self.padding()}{utils.deserialize_int(obj.bigint_val)}\n"
        if obj.HasField('float_val'):
            return f"{self.padding()}{obj.float_val}\n"
        if obj.HasField('str_val'):
            return f"{self.padding()}{obj.str_val}\n"
        if obj.HasField('bytes_val'):
            return f"{self.padding()}{obj.bytes_val}\n"
        if obj.HasField('bool_val'):
            return f"{self.padding()}{obj.bool_val}\n"
        if obj.HasField('nonetype_flag'):
            return f"{self.padding()}None\n"

        if id in self.seen:
            return f"{self.padding()}*ref<{id}>\n"
        self.seen.add(id)

        if obj.HasField('list_val'):
            return self.format_collection(id, obj.list_val.fields)
        if obj.HasField('tuple_val'):
            return self.format_collection(id, obj.tuple_val.fields, "()")
        if obj.HasField('deque_val'):
            return self.format_collection(id, obj.deque_val.fields)
        if obj.HasField('set_val'):
            return self.format_collection(id, obj.set_val.fields, ("set(", ")"))

        if obj.HasField('dict_val'):
            ret = self.padding() + f"<{id}>" +"{\n"
            self.indent += 1
            for entry in obj.dict_val.entries:
                key = self._stringify(entry.key).strip()
                val = self._stringify(entry.val).strip()
                ret += f"{self.padding()}{key}: {val}\n"
            self.indent -= 1
            ret += self.padding() + "}\n"
            return ret

        if obj.HasField('object_val'):
            typ = obj.object_val.type
            if typ in _serializable_object_registry:
                if hasattr(_serializable_object_registry[typ], 'stringify'):
                    return _serializable_object_registry[typ].stringify(self, id, obj.object_val)
            if typ in _custom_serializable_object_registry:
                if _custom_serializable_object_registry[typ][3] != None:
                    return _custom_serializable_object_registry[typ][3](self, id, obj.object_val)

            ret = self.padding() + obj.object_val.type + "{" + f"<{id}>\n"
            self.indent += 1
            for entry in obj.object_val.fields.entries:
                key = self._stringify(entry.key).strip()
                val = self._stringify(entry.val).strip()
                ret += f"{self.padding()}{key}: {val}\n"
                if obj.object_val.HasField('custom'):
                    ret += f"{self.padding()}custom={obj.object_val.custom}\n"
            self.indent -= 1

            ret += self.padding() + "}" + "\n"
            return ret

        if obj.HasField('array_val'):
            arr = array(chr(obj.array_val.typecode))
            arr.frombytes(obj.array_val.data)
            return f"<{id}>[{self.padding()}<{id}>{arr}]\n"

        return f"<{id}>???"

    def padding(self) -> str:
        return "  " * self.indent

    def format_collection(self, id: str, fields: list[str], grouping_operators="[]") -> str:
        ret = f"{self.padding()}<{id}>" + grouping_operators[0] + "\n"
        self.indent += 1
        ret += "".join([self._stringify(id) for id in fields])
        self.indent -= 1
        ret += self.padding() + grouping_operators[1] + "\n"
        return ret


def stringify_state(serialized: serialization_pb2.SerializedPackage) -> str:
    stringifier = _Stringifier(serialized)
    return stringifier.stringify()

