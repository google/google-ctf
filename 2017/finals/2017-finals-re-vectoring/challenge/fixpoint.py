#!/usr/bin/python
#
# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from pwnlib.util.lists import concat_all
from pwnlib.util.packing import flat

__all__ = ['Align', 'Location', 'Buf', 'fixpoint']

class Align(object):
    def __init__(self, alignment, value = b'\x00'):
        self.alignment = alignment
        self.value = value
    def __eq__(self, other):
        return type(other) == Align and \
            self.alignment == other.alignment and \
            self.value == other.value

class Location(object):
    def __init__(self, location):
        self.location = location
    def __eq__(self, other):
        return type(other) == Location and self.location == other.location

class Buf(object):
    _children = []
    _updated = False
    _changed = False
    _called = False
    _name = None
    value = ''
    ptr = 0
    endptr = 0

    def __init__(self, name):
        self._name = name

    def _reset(self):
        self._changed = False
        self._updated = False
        self._called = False

    def _update(self, location):
        if self._updated:
            raise Exception("The buffer %r was included in the tree twice" %
                            self._name)
        self._updated = True
        self.ptr = location

        output = []
        for c in self._children:
            if isinstance(c, Align):
                needed = (c.alignment - location) % c.alignment
                location += needed
                repetitions = (needed + len(c.value) - 1) / len(c.value)
                generated = (c.value * repetitions)[:needed]
                assert len(generated) == needed
                output.append(generated)
            elif isinstance(c, Location):
                location = c.location
            elif isinstance(c, Buf):
                location = c._update(location)
                output.append(c.value)
            else:
                output.append(c)
                location += len(c)

        self.value = ''.join(output)
        self.endptr = location
        return location

    def __call__(self, *args):
        self._called = True
        old_children = self._children
        self._children = concat_all(args)

        for n, c in enumerate(self._children):
            if not isinstance(c, (Align, Location, Buf)):
                self._children[n] = flat(c)

        if self._children != old_children:
            self._changed = True
        return self

    def __int__(self):
        return self.ptr

class BufManager(object):
    def __init__(self):
        self._bufs = {}

    def __getitem__(self, item):
        if item not in self._bufs:
            self._bufs[item] = Buf(item)
        return self._bufs[item]

    def __getattr__(self, attr):
        return self[attr]

def fixpoint(f):
    roots = []
    manager = BufManager()

    # The termination criteria of this loop is, that we want to continue running
    # as long as something change compared to the old run. We detect the change
    # inside __call__ on the Buf. If it gets called with arguments that are not
    # exactly the same as the old ones (after concat_all and flat), then we set
    # _changed on the object.
    done = False
    while not done:
        done = True
        for b in list(manager._bufs.values()) + roots:
            b._reset()
        output = f(manager)
        # If f does not call a buffer, then that should be equivalent to calling
        # it without arguments
        for b in manager._bufs.values():
            if not b._called:
                b()

        if not isinstance(output, tuple):
            output = (output,)
        if len(output) != len(roots):
            roots = [Buf('root_%d' % n) for n in range(len(output))]
        for root, out in zip(roots, output):
            root(out)

        location = 0
        for root in roots:
            location = root._update(location)

        for b in list(manager._bufs.values()) + roots:
            if b._changed:
                done = False
            if not b._updated:
                raise Exception("The buffer %r was not included in the tree" %
                                b._name)

    if len(roots) == 1:
        return roots[0].value
    else:
        return [root.value for root in roots]
