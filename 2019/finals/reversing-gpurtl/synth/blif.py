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

from typing import Optional, Dict, Tuple, AbstractSet, Sequence, Collection, Iterable
from enum import Enum
from abc import ABC, abstractproperty

from lark import Lark, Transformer, v_args


class Var:
    def __init__(self, name: str):
        self._name = name
        self._mv: Optional["ModelVar"] = None

    def set_mv(self, mv: "ModelVar"):
        self._mv = mv

    @property
    def name(self) -> str:
        return self._name

    @property
    def mv(self) -> "ModelVar":
        assert self._mv is not None
        return self._mv

    @property
    def src_var(self) -> "Var":
        return self.mv.src_var

    @property
    def src_cmd(self) -> "Command":
        return self.mv.src_cmd

    @property
    def clock(self) -> bool:
        return self.mv.clock


class Command(ABC):
    @abstractproperty
    def inputs(self) -> Sequence[Var]:
        pass

    @abstractproperty
    def outputs(self) -> Sequence[Var]:
        pass

    @abstractproperty
    def clocks(self) -> Sequence[Var]:
        pass


class LUTProg:
    def __init__(self, ins: Sequence[str], out: bool):
        self._ins = ins
        self._out = out

    def eval(self, bits: Sequence[bool]) -> bool:
        if all(i == "-" or (i == "1") == b for i, b in zip(self._ins, bits)):
            return self._out
        return False


class LUT(Command):
    def __init__(
        self, inputs: Sequence[Var], output: Var, prog_lines: Iterable[LUTProg]
    ):
        self._inputs = inputs
        self._output = output
        self._prog_lines = prog_lines

    def eval(self, bits: Sequence[bool]) -> bool:
        return any(l.eval(bits) for l in self._prog_lines)

    @property
    def size(self) -> int:
        return len(self._inputs)

    @property
    def inputs(self) -> Sequence[Var]:
        return self._inputs

    @property
    def outputs(self) -> Sequence[Var]:
        return [self._output]

    @property
    def clocks(self) -> Sequence[Var]:
        return []

    @property
    def output(self) -> Var:
        return self._output


class RegType(Enum):
    FE = "fe"
    RE = "re"
    AH = "ah"
    AL = "al"
    AS = "as"


class RegInit(Enum):
    ZERO = 0
    ONE = 1
    DONT_CARE = 2
    UNKNOWN = 3


class Reg(Command):
    def __init__(
        self, inp: Var, output: Var, ty: RegType, control: Optional[Var], init: RegInit
    ):
        self._input = inp
        self._output = output
        self._type = ty
        self._control = control
        self._init = init

    @property
    def inputs(self) -> Sequence[Var]:
        return [self._input]

    @property
    def outputs(self) -> Sequence[Var]:
        return [self._output]

    @property
    def clocks(self) -> Sequence[Var]:
        if self._control is not None:
            return [self._control]
        return []

    @property
    def input(self) -> Var:
        return self._input

    @property
    def output(self) -> Var:
        return self._output

    @property
    def clock(self) -> Optional[Var]:
        return self._control


class ModelVar:
    def __init__(self, name: str):
        self._name = name
        self._src: Optional[Tuple[Command, Var]] = None
        self.clock = False

    def set_src(self, cmd: Command, v: Var):
        assert self._src is None
        assert v.mv is self
        self._src = (cmd, v)

    @property
    def name(self) -> str:
        return self._name

    @property
    def src_var(self) -> Var:
        assert self._src is not None
        return self._src[1]

    @property
    def src_cmd(self) -> Command:
        assert self._src is not None
        return self._src[0]


class ModelVars:
    def __init__(self):
        self._cache: Dict[str, ModelVar] = {}

    def register(self, v: Var) -> ModelVar:
        name = v.name
        if name not in self._cache:
            self._cache[name] = ModelVar(name)
        v.set_mv(self._cache[name])
        return self._cache[name]

    def register_src(self, v: Var, cmd: Command) -> ModelVar:
        mv = self.register(v)
        mv.set_src(cmd, v)
        return mv

    def register_cmd_reversed(self, cmd: Command):
        for v in cmd.inputs:
            self.register_src(v, cmd)
        for v in cmd.outputs:
            self.register(v)
        for v in cmd.clocks:
            mv = self.register_src(v, cmd)
            mv.clock = True

    def register_cmd(self, cmd: Command):
        for v in cmd.inputs:
            self.register(v)
        for v in cmd.outputs:
            self.register_src(v, cmd)
        for v in cmd.clocks:
            mv = self.register(v)
            mv.clock = True

    def vars(self) -> Collection[ModelVar]:
        return self._cache.values()


class Model(Command):
    def __init__(
        self,
        name: str,
        inputs: Sequence[Var],
        outputs: Sequence[Var],
        clocks: Sequence[Var],
        commands: AbstractSet[Command],
    ):
        self._name = name
        self._inputs = inputs
        self._outputs = outputs
        self._clocks = clocks
        self._commands = commands

        self._vars = ModelVars()
        self._vars.register_cmd_reversed(self)
        for cmd in self._commands:
            self._vars.register_cmd(cmd)

    @property
    def inputs(self) -> Sequence[Var]:
        return self._inputs

    @property
    def outputs(self) -> Sequence[Var]:
        return self._outputs

    @property
    def clocks(self) -> Sequence[Var]:
        return self._clocks

    @property
    def inner_vars(self) -> Collection[ModelVar]:
        return self._vars.vars()

    @property
    def commands(self) -> AbstractSet[Command]:
        return self._commands


@v_args(inline=True)
class BlifTransformer(Transformer):
    def blif(self, model):
        return model

    def model(self, name, inputs, outputs, clocks, commands):
        return Model(name, inputs, outputs, clocks, commands)

    def commands(self, *cmds):
        return cmds

    def model_inputs(self, *varz):
        return [Var(v) for v in varz]

    def model_inputs_mul(self, *inputs):
        return [i for sub in inputs for i in sub]

    def model_outputs(self, *varz):
        return [Var(v) for v in varz]

    def model_outputs_mul(self, *outputs):
        return [i for sub in outputs for i in sub]

    def model_clocks(self, *varz):
        return [Var(v) for v in varz]

    def model_clocks_mul(self, *clocks):
        return [i for sub in clocks for i in sub]

    def model_name(self, name):
        return name

    def reg(self, inp, output, ty, control, init):
        return Reg(inp, output, ty, control, init)

    def reg_input(self, var):
        return Var(var)

    def reg_output(self, var):
        return Var(var)

    def reg_init(self, val):
        return RegInit(int(val))

    def reg_control(self, varnil):
        if varnil == "NIL":
            return None
        return Var(varnil)

    def reg_type(self, ty):
        return RegType(ty)

    def lut(self, inputs, output, progs):
        return LUT(inputs, output, progs)

    def lut_progs(self, *progs):
        return progs

    def lut_prog(self, inp, output):
        return LUTProg(inp, output)

    def lut_inputs(self, *varz):
        return [Var(v) for v in varz]

    def lut_output(self, var):
        return Var(var)

    def lut_prog_input(self, *prog_inputs):
        return prog_inputs

    def lut_prog_output(self, prog_output):
        return int(prog_output)


def get_parser():
    return Lark.open("blif.lark", start="blif")
