# Copyright 2019 Google LLC

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     https://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from typing import List, Optional, Dict, Sequence, Mapping, MutableMapping
from abc import ABC, abstractproperty
import math
import struct

from simanneal import Annealer

import blif


class DummyVar(blif.Var):
    def __init__(self):
        super(DummyVar, self).__init__("dummy")


class Location(ABC):
    @abstractproperty
    def loci(self) -> int:
        pass

    @abstractproperty
    def name(self) -> str:
        pass


class InputPort(Location):
    def __init__(self, v: blif.Var, loci: int):
        self._v = v
        self._loci = loci

    @staticmethod
    def dummy(loci: int) -> "InputPort":
        return InputPort(DummyVar(), loci)

    @property
    def is_dummy(self) -> bool:
        return isinstance(self._v, DummyVar)

    @property
    def loci(self) -> int:
        return self._loci

    @property
    def name(self) -> str:
        return self._v.name

    def __str__(self) -> str:
        return "{}@0x{:x}".format(self.name, self.loci)


class Jump:
    def __init__(self, dest: Location, index: int):
        self._dest = dest
        self._index = index

    @property
    def index(self) -> int:
        return self._index

    def as_bin(self) -> bytes:
        return struct.pack(">I", self._dest.loci)

    def __lt__(self, other) -> bool:
        return self.index < other.index


class BLE:
    class _LUTOutput(Location):
        def __init__(self, inner: "BLE", var: blif.Var):
            self._inner = inner
            self._var = var

        @property
        def loci(self) -> int:
            return self._inner.lut_loci

        @property
        def name(self) -> str:
            return self._var.name

        def __str__(self) -> str:
            return self.name

    @property
    def lut_output(self) -> "BLE._LUTOutput":
        return BLE._LUTOutput(self, self._lut.output)

    class _RegOutput(Location):
        def __init__(self, inner: "BLE", var: blif.Var):
            self._inner = inner
            self._var = var

        @property
        def loci(self) -> int:
            return self._inner.lut_loci + 1

        @property
        def name(self) -> str:
            return self._var.name

        def __str__(self) -> str:
            return self.name

    @property
    def reg_output(self) -> "BLE._RegOutput":
        assert self._reg is not None, "no reg for {}".format(self.lut_output.name)
        return BLE._RegOutput(self, self._reg.output)

    def has_reg(self) -> bool:
        return self._reg is not None

    def __init__(self, lut: blif.LUT, reg: Optional[blif.Reg], loci: int):
        self._lut = lut
        self._reg = reg
        self._loci = loci
        self._connected: Dict[blif.ModelVar, Location] = {}

    @staticmethod
    def dummy(loci: int) -> "BLE":
        return BLE(blif.LUT([], DummyVar(), set()), None, loci)

    @property
    def is_dummy(self) -> bool:
        return isinstance(self._lut.output, DummyVar)

    def connect(self, mv_index: Mapping[blif.ModelVar, Location]):
        for i in self._lut.inputs:
            assert i.mv in mv_index, "could not find {} in index".format(i.mv.name)
            self._connected[i.mv] = mv_index[i.mv]

    @property
    def lut_loci(self) -> int:
        return self._loci

    def cost(self) -> float:
        cost = 0.0
        for l in self._connected.values():
            d = abs(l.loci - self._loci)
            cost += 0.01 * d
            if d > 256:
                cost += 4.0

        return cost

    def _need_jump(self, mv: blif.ModelVar) -> bool:
        a = self._connected[mv].loci - self._loci + 0x400
        return not 0 <= a < 0x800

    def _get_lut(self) -> int:
        if self._lut is None:
            return 0
        r = 0
        size = self._lut.size
        mod = 1 << size
        format_str = "{:0" + "{}".format(size) + "b}"
        for i in range(0, 16):
            bits = [c == "1" for c in format_str.format(i % mod)]
            if self._lut.eval(bits):
                r |= 1 << i
        assert r < 2 ** 16, "lut programming is {:x}".format(r)
        return r

    def _get_input_addrs(self, jumps: Mapping[blif.ModelVar, Jump]) -> List[int]:
        if self._lut is None:
            return [0, 0, 0, 0]

        def calc_addr(mv: blif.ModelVar) -> int:
            if self._need_jump(mv):
                assert mv in jumps
                a = jumps[mv].index
                assert 0 <= a < 0x800, "jump index is 0x{:x} for {} in lut {}".format(
                    a, mv.name, self.lut_output.name
                )
                a |= 0x800
            else:
                a = self._connected[mv].loci - self._loci + 0x400
                assert 0 <= a < 0x800, "input addr is 0x{:x} for {} in lut {}".format(
                    a, mv.name, self.lut_output.name
                )

            assert 0 <= a < 0x1000, "input addr is 0x{:x} for {} in lut {}".format(
                a, mv.name, self.lut_output.name
            )
            return a

        addrs = [0 for _ in range(self._lut.size, 4)] + [
            calc_addr(i.mv) for i in self._lut.inputs
        ]
        return addrs

    def as_bin(self, jumps: Mapping[blif.ModelVar, Jump]) -> bytes:
        addrs = self._get_input_addrs(jumps)
        a = self._get_lut() << 16 | addrs[0] << 4 | addrs[1] >> 8
        b = (addrs[1] & 0xFF) << 24 | addrs[2] << 12 | addrs[3]
        return struct.pack(">II", a, b)

    def calc_jumps(self, r: MutableMapping[blif.ModelVar, Jump]):
        for i in self._lut.inputs:
            if self._need_jump(i.mv) and i.mv not in r:
                r[i.mv] = Jump(self._connected[i.mv], len(r))

    def __str__(self) -> str:
        reg_out = self._reg.output.name if self._reg is not None else "None"
        return "ble@0x{:x}: inputs[{}], lut out({}), reg out({}), lut(0x{:x})".format(
            self.lut_loci,
            ",".join(v.name for v in self._lut.inputs),
            self._lut.output.name,
            reg_out,
            self._get_lut(),
        )


class Configuration(Annealer):
    def __init__(
        self,
        inputs: Sequence[InputPort],
        bles: Sequence[BLE],
        outputs: Mapping[str, Location],
    ):
        self._inputs = inputs
        self._bles = bles
        self._outputs = outputs

    def cost(self) -> float:
        return sum(ble.cost() for ble in self._bles)

    @property
    def block_count(self) -> int:
        return len(self._bles) // 256

    @property
    def port_bits(self) -> int:
        return len(self._inputs)

    @property
    def jumps(self) -> Dict[blif.ModelVar, Jump]:
        r: Dict[blif.ModelVar, Jump] = {}
        for ble in self._bles:
            ble.calc_jumps(r)
        return r

    def as_bin(self) -> bytes:
        assert len(self._bles) % 256 == 0
        assert len(self._inputs) % 8 == 0

        jumps = self.jumps
        jump_count = len(jumps)

        return (
            b"gpurtlPC"
            + struct.pack(">IHH", self.block_count, self.port_bits, jump_count)
            + b"".join(ble.as_bin(jumps) for ble in self._bles)
            + b"".join(jump.as_bin() for jump in sorted(jumps.values()))
        )

    @property
    def outputs(self) -> Mapping[str, Location]:
        return self._outputs

    @property
    def inputs(self) -> Mapping[str, Location]:
        return {p.name: p for p in self._inputs if not p.is_dummy}

    @property
    def inner_vars(self) -> Mapping[str, Location]:
        r: Dict[str, Location] = {}
        for ble in self._bles:
            if ble.is_dummy:
                continue
            lut = ble.lut_output
            r[lut.name] = lut
            if ble.has_reg():
                reg = ble.reg_output
                r[reg.name] = reg

        return r

    def __str__(self) -> str:
        return "config:\ninputs[{}],\nbles[{}],\noutputs[{}]".format(
            ",\n  ".join(str(i) for i in self._inputs),
            ",\n  ".join(str(b) for b in self._bles),
            ",\n  ".join(self._outputs.keys()),
        )

    @staticmethod
    def from_model(m: blif.Model) -> "Configuration":
        loci: int = 0
        ports: List[InputPort] = []
        bles: List[BLE] = []
        mv_index: Dict[blif.ModelVar, Location] = {}

        for inp in m.inputs:
            if inp.clock:
                continue
            ip = InputPort(inp, loci)
            loci += 1
            ports.append(ip)
            mv_index[inp.mv] = ip

        while loci % 8 != 0:
            ports.append(InputPort.dummy(loci))
            loci += 1

        for c in m.commands:
            if isinstance(c, blif.Reg):
                source = c.input.src_cmd
                assert isinstance(source, blif.LUT), "reg source is {}".format(
                    c.input.name
                )
                ble = BLE(source, c, loci)
                loci += 2
                bles.append(ble)
                mv_index[c.output.mv] = ble.reg_output
                mv_index[source.output.mv] = ble.lut_output

        for mv in m.inner_vars:
            if mv.clock:
                continue
            if mv not in mv_index:
                assert isinstance(
                    mv.src_cmd, blif.LUT
                ), "inner var {} is not a LUT".format(mv.name)
                if any(inp.clock for inp in mv.src_cmd.inputs):
                    continue
                ble = BLE(mv.src_cmd, None, loci)
                loci += 2
                bles.append(ble)
                mv_index[mv] = ble.lut_output

        for ble in bles:
            ble.connect(mv_index)

        desired_bles = int(math.ceil((len(bles) * 1.2) / 256)) * 256
        for _ in range(len(bles), desired_bles):
            bles.append(BLE.dummy(loci))
            loci += 2

        assert len(bles) == desired_bles

        outputs = {v.name: mv_index[v.mv] for v in m.outputs}

        return Configuration(ports, bles, outputs)
