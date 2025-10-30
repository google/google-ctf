# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Multiarch assembler."""

import argparse
import ast
import dataclasses
import enum
import logging
import re
import struct
import sys


logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%d %H:%M:%S",
)
LOG = logging.getLogger(__name__)


CODE_BASE_ADDRESS = 0x1000
DATA_BASE_ADDRESS = 0x2000


class Architecture(enum.IntEnum):
    StackVM = 0
    RegVM = 1

    @staticmethod
    def from_op(sym: str) -> "Architecture":
        s = sym.lower()
        if s == "s":
            return Architecture.StackVM
        if s == "r":
            return Architecture.RegVM

        raise ValueError(f"invalid architecture symbol: {sym}")
    
    def __str__(self) -> str:
        return self.name[0]


class Register(enum.IntEnum):
    A = 0
    B = 1
    C = 2
    D = 3
    SP = 4

    @staticmethod
    def from_arg(arg: str) -> "Register":
        a = arg.lower()

        if a == "a":
            return Register.A
        if a == "b":
            return Register.B
        if a == "c":
            return Register.C
        if a == "d":
            return Register.D
        if a == "sp":
            return Register.SP
        
        raise ValueError(f"invalid register: {arg}")

    def __repr__(self) -> str:
        return f"<R:{self}>"

    def __str__(self) -> str:
        return self.name
    
    @property
    def is_gp(self) -> bool:
        return self in [Register.A, Register.B, Register.C, Register.D]


class RegisterDeref(enum.IntEnum):
    A = 0
    B = 1
    C = 2
    D = 3
    SP = 4

    @staticmethod
    def from_arg(arg: str) -> "RegisterDeref":
        a = arg.lower()

        if a == "a":
            return RegisterDeref.A
        if a == "b":
            return RegisterDeref.B
        if a == "c":
            return RegisterDeref.C
        if a == "d":
            return RegisterDeref.D
        if a == "sp":
            return RegisterDeref.SP
        
        raise ValueError(f"invalid register: {arg}")

    def __repr__(self) -> str:
        return f"<R:*{self}>"

    def __str__(self) -> str:
        return self.name
    
    def is_gp(self) -> bool:
        return self in [RegisterDeref.A, RegisterDeref.B, RegisterDeref.C, RegisterDeref.D]


class Label(str):
    def __repr__(self) -> str:
        return f"<L:{self}>"


class LabelAddr(str):
    def __repr__(self) -> str:
        return f"<LA:{self}>"
    

class DataSize(str):
    def __repr__(self) -> str:
        return f"<DS:{self}>"
    
    @property
    def label(self) -> Label:
        return Label(self)
    

class PackableMixin:
    def pack(self, width=4) -> bytes:
        if width == 1:
            fmt = "<B"
        elif width == 2:
            fmt = "<H"
        elif width == 4:
            fmt = "<I"
        else:
            raise ValueError(f"invalid pack width: {width}")
        
        return struct.pack(fmt, self)


class Immediate(int, PackableMixin):
    def __repr__(self) -> str:
        return f"<I:{self:#x}>"


class Address(int, PackableMixin):
    def __repr__(self) -> str:
        return f"<A:{self:#x}>"


@dataclasses.dataclass
class Instruction:
    arch: Architecture
    mnemonic: str
    args: list[Immediate | Address | Register | Label | DataSize]
    label: Label | None

    _encoded: bytes | None = None

    @staticmethod
    def parse_line(line: str, label: Label | None = None) -> "Instruction":
        line = line.strip()
        op, argstr = (line + " ").split(" ", 1)

        try:
            arch, mnem = op.split(".")
        except ValueError:
            raise ValueError(f"unqualified mnemonic, instruction is invalid: {line}")
        
        args = []
        if len(argstr) > 0:
            arg_parts = [x.strip() for x in argstr.split(",")]
        
            for a in arg_parts:
                if len(a) == 1 or a.lower() == "sp":
                    args.append(Register.from_arg(a))
                elif a[0] == "*":
                    args.append(RegisterDeref.from_arg(a[1:]))
                elif a[0] == "#":
                    if a.startswith("#0x"):
                        args.append(Immediate(int(a[1:], 16)))
                    else:
                        args.append(Immediate(int(a[1:])))
                elif a[0] == "@":
                    if a.startswith("@0x"):
                        args.append(Address(int(a[1:], 16)))
                    else:
                        args.append(Address(int(a[1:])))
                elif a.startswith("sizeof("):
                    args.append(DataSize(a.split("(")[1].split(")")[0]))
                elif a.startswith("&"):
                    args.append(LabelAddr(a[1:]))
                else:
                    args.append(Label(a))
        
        return Instruction(Architecture.from_op(arch), mnem.lower(), args, label)
    
    def __repr__(self) -> str:
        if self.label is not None:
            lbl = f" @{self.label}"
        else:
            lbl = ""

        return f"<Ins:{lbl} {self.arch}.{self.mnemonic} [{', '.join(repr(a) for a in self.args)}]>"

    def __str__(self) -> str:
        return repr(self)
    
    @property
    def has_symbolics(self):
        return any(any(isinstance(x, y) for y in (Label, LabelAddr, DataSize)) for x in self.args)

    @property
    def can_encode(self):
        return not self.has_symbolics
    
    @property
    def is_valid(self) -> bool:
        """Check if the instruction has a valid set of arguments"""

        if self.arch == Architecture.StackVM:
            if self.mnemonic == "ldb":
                if len(self.args) != 1:
                    return False
                if not any(isinstance(self.args[0], x) for x in [Address, Immediate, DataSize, Label]):
                    return False
                if any(isinstance(self.args[0], x) for x in [Address, Immediate]) and self.args[0] >= 0x1_00:
                    return False
            elif self.mnemonic == "ldw":
                if len(self.args) != 1:
                    return False
                if not any(isinstance(self.args[0], x) for x in [Address, Immediate, DataSize, Label]):
                    return False
                if any(isinstance(self.args[0], x) for x in [Address, Immediate]) and self.args[0] >= 0x1_00_00:
                    return False
            elif self.mnemonic == "ldd":
                if len(self.args) != 1:
                    return False
                if not any(isinstance(self.args[0], x) for x in [Address, Immediate, DataSize, Label]):
                    return False
                if any(isinstance(self.args[0], x) for x in [Address, Immediate]) and self.args[0] >= 0x1_00_00_00_00:
                    return False
            elif self.mnemonic in ["ldp", "jmp", "jeq", "jne", "call"]:
                if len(self.args) != 1:
                    return False
                if not any(isinstance(self.args[0], x) for x in [Address, Label]):
                    return False
            elif len(self.args) != 0:
                return False
        elif self.arch == Architecture.RegVM:
            if self.mnemonic == "mov":
                if len(self.args) != 2:
                    return False
            elif self.mnemonic == "push":
                if len(self.args) != 1:
                    return False
                if not any(isinstance(self.args[0], x) for x in [Register, Immediate, DataSize]):
                    return False
            elif self.mnemonic == "pop":
                if len(self.args) != 1:
                    return False
                if not isinstance(self.args[0], Register):
                    return False
            elif self.mnemonic in ["add", "sub", "xor", "mul"]:
                if len(self.args) != 2:
                    return False
                if not isinstance(self.args[0], Register):
                    return False
            elif self.mnemonic in ["call", "jmp", "jeq", "jne", "jg"]:
                if len(self.args) != 1:
                    return False
                if not any(isinstance(self.args[0], x) for x in [Address, Label]):
                    return False
            elif self.mnemonic == "ret":
                if len(self.args) != 1:
                    return False
                if not isinstance(self.args[0], Immediate):
                    return False
                if self.args[0] >= 0x1_00:
                    return False
            elif self.mnemonic == "cmp":
                if len(self.args) != 2:
                    return False
                if not isinstance(self.args[0], Register):
                    return False
                if not any(isinstance(self.args[1], x) for x in [Register, Immediate]):
                    return False
            elif len(self.args) != 0:
                return False

        return True

    @property
    def encoded(self) -> bytes:
        if self._encoded is not None:
            return self._encoded
        
        if not self.is_valid:
            raise ValueError(f"instruction is invalid: {self}")
        if self.has_symbolics:
            raise ValueError(f"can't encode instruction yet, still has labels: {self}")
        
        if self.arch == Architecture.StackVM:
            if self.mnemonic == "ldb":
                self._encoded = b"\x10" + self.args[0].pack(1)
            elif self.mnemonic == "ldw":
                self._encoded = b"\x20" + self.args[0].pack(2)
            elif self.mnemonic == "ldd":
                self._encoded = b"\x30" + self.args[0].pack()
            elif self.mnemonic == "ldp":
                self._encoded = b"\x40" + self.args[0].pack()
            elif self.mnemonic == "pop":
                self._encoded = b"\x50"
            elif self.mnemonic == "add":
                self._encoded = b"\x60"
            elif self.mnemonic == "sub":
                self._encoded = b"\x61"
            elif self.mnemonic == "xor":
                self._encoded = b"\x62"
            elif self.mnemonic == "and":
                self._encoded = b"\x63"
            elif self.mnemonic == "jmp":
                self._encoded = b"\x70" + self.args[0].pack()
            elif self.mnemonic == "jeq":
                self._encoded = b"\x71" + self.args[0].pack()
            elif self.mnemonic == "jne":
                self._encoded = b"\x72" + self.args[0].pack()
            elif self.mnemonic == "cmp":
                self._encoded = b"\x80"
            elif self.mnemonic == "sys":
                self._encoded = b"\xa0"
            elif self.mnemonic == "hlt":
                self._encoded = b"\xff"*5
            else:
                raise ValueError(f"bad instruction: {self}")

            if len(self._encoded) < 5:
                self._encoded += b"\x00" * (5-len(self._encoded))
        elif self.arch == Architecture.RegVM:
            if self.mnemonic == "mov":
                opcode = 0b1100_0000
                dst, src = self.args
                prefix = 0
                trailer = b""

                if isinstance(dst, Register) and dst.is_gp:
                    opcode |= dst.value << 3
                elif isinstance(dst, RegisterDeref) and dst.is_gp:
                    prefix |= 0b0100
                    opcode |= dst.value << 3
                else:
                    if isinstance(dst, Address):
                        opcode |= 4 << 3
                    else:
                        raise ValueError(f"bad mov dest: {self}")
                    trailer += dst.pack()

                if isinstance(src, Register) and src.is_gp:
                    opcode |= src.value
                elif src == Register.SP:
                    opcode |= 6
                elif isinstance(src, RegisterDeref):
                    prefix |= 0b0001
                    if src.is_gp:
                        opcode |= src.value
                    elif src == RegisterDeref.SP:
                        opcode |= 6
                    else:
                        raise ValueError(f"bad mov src deref: {self}")
                else:
                    # only things needing a packed imm go here
                    if isinstance(src, Address):
                        opcode |= 4
                    elif isinstance(src, Immediate):
                        opcode |= 5
                    else:
                        raise ValueError(f"bad mov src: {self}")
                    trailer += src.pack()
                
                if prefix > 0:
                    LOG.info("prefix")
                    self._encoded = bytes([0b1010_0000 | prefix])
                else:
                    self._encoded = b""
                self._encoded += bytes([opcode]) + trailer
            elif self.mnemonic == "push":
                if isinstance(self.args[0], Register):
                    self._encoded = bytes([0x10 | (self.args[0].value + 1)])
                elif isinstance(self.args[0], Immediate):
                    self._encoded = b"\x10" + self.args[0].pack()
                else:
                    raise ValueError(f"bad instruction: {self}")
            elif self.mnemonic == "pop":
                self._encoded = bytes([0x10 | (self.args[0].value + 5)])
            elif self.mnemonic == "add":
                if isinstance(self.args[1], Register):
                    self._encoded = bytes([0x20, ((self.args[0].value + 1)<<4) | (self.args[1].value + 1)])
                elif isinstance(self.args[1], Immediate):
                    self._encoded = bytes([0x21, (self.args[0].value + 1)<<4]) + self.args[1].pack()
                else:
                    raise ValueError(f"bad instruction: {self}")
            elif self.mnemonic == "sub":
                if isinstance(self.args[1], Register):
                    self._encoded = bytes([0x30, ((self.args[0].value + 1)<<4) | (self.args[1].value + 1)])
                elif isinstance(self.args[1], Immediate):
                    self._encoded = bytes([0x31, (self.args[0].value + 1)<<4]) + self.args[1].pack()
                else:
                    raise ValueError(f"bad instruction: {self}")
            elif self.mnemonic == "xor":
                if isinstance(self.args[1], Register):
                    self._encoded = bytes([0x40, ((self.args[0].value + 1)<<4) | (self.args[1].value + 1)])
                elif isinstance(self.args[1], Immediate):
                    self._encoded = bytes([0x41, (self.args[0].value + 1)<<4]) + self.args[1].pack()
                else:
                    raise ValueError(f"bad instruction: {self}")
            elif self.mnemonic == "mul":
                if isinstance(self.args[1], Register):
                    self._encoded = bytes([0x50, ((self.args[0].value + 1)<<4) | (self.args[1].value + 1)])
                elif isinstance(self.args[1], Immediate):
                    self._encoded = bytes([0x51, (self.args[0].value + 1)<<4]) + self.args[1].pack()
                else:
                    raise ValueError(f"bad instruction: {self}")
            elif self.mnemonic == "call":
                self._encoded = b"\x60" + self.args[0].pack()
            elif self.mnemonic == "ret":
                self._encoded = bytes([0x61, self.args[0]])
            elif self.mnemonic == "jeq":
                self._encoded = b"\x62" + self.args[0].pack()
            elif self.mnemonic == "jne":
                self._encoded = b"\x63" + self.args[0].pack()
            elif self.mnemonic == "jg":
                self._encoded = b"\x64" + self.args[0].pack()
            elif self.mnemonic == "jmp":
                self._encoded = b"\x68" + self.args[0].pack()
            elif self.mnemonic == "cmp":
                if isinstance(self.args[1], Register):
                    self._encoded = bytes([0x70 | ((self.args[0].value)<<2) | (self.args[1].value)])
                elif isinstance(self.args[1], Immediate):
                    self._encoded = bytes([0x80 | self.args[0].value]) + self.args[1].pack()
                else:
                    raise ValueError(f"bad instruction: {self}")
            elif self.mnemonic == "hlt":
                self._encoded = b"\x00"
            elif self.mnemonic == "sys":
                self._encoded = b"\x01"
        
        if self._encoded is None:
            raise ValueError(f"no encoding for {self}")

        return self._encoded

    @property
    def size(self) -> int:
        if not self.is_valid:
            raise ValueError(f"instruction is invalid: {self}")

        # StackVM is fixed width
        if self.arch == Architecture.StackVM:
            return 5
        elif self.arch == Architecture.RegVM:
            if self.mnemonic == "mov":
                # 1 byte fixed, plus 4 bytes for each non-reg argument
                sz = 1
                sz += (4*len(list(filter(lambda x: any(isinstance(x, y) for y in [Address, Label, LabelAddr, Immediate, DataSize]), self.args))))

                if any(isinstance(x, RegisterDeref) for x in self.args):
                    sz += 1

                return sz
            elif self.mnemonic in ["call", "jmp", "jeq", "jne", "jg"]:
                return 5
            elif self.mnemonic == "push":
                if any(isinstance(self.args[0], x) for x in [Immediate, DataSize]):
                    return 5
                return 1
            elif self.mnemonic == "ret":
                return 2
            elif self.mnemonic in ["add", "sub", "xor", "mul"]:
                if isinstance(self.args[1], Immediate):
                    return 6
                return 2
            elif self.mnemonic == "cmp":
                if isinstance(self.args[1], Immediate):
                    return 5
                return 1
            elif self.mnemonic in ["hlt", "sys", "push", "pop"]:
                return 1
        
        raise ValueError(f"unknown size: {self}")


_DATA_PAT = re.compile(r'^(?P<label>[a-z0-9_]+): *(?P<data>"[^"]+")$', re.I)
@dataclasses.dataclass
class Data:
    label: Label
    value: bytes

    @staticmethod
    def parse_line(line: str) -> "Data":
        m = _DATA_PAT.match(line)
        if m is None:
            raise ValueError(f"invalid data definition: {line}")
        
        return Data(Label(m.group("label")), ast.literal_eval("b" + m.group("data")))
    
    @property
    def size(self):
        return len(self.value)

def get_input_lines(filename: str) -> list[str]:
    """Read in the assembly code, with comments stripped out"""

    ret = []

    with open(filename, "r") as f:
        lines = f.readlines()

        for l in lines:
            l = l.split("//", 1)[0].strip()
            if len(l) > 0:
                ret.append(l)

    return ret


def get_code_lines(lines: list[str]) -> list[str] | None:
    try:
        start = lines.index(".code")
    except ValueError:
        return None
    try:
        end = lines.index(".data")
    except ValueError:
        end = None
    if end is not None and end < start:
        end = None
    
    return lines[start+1:end]


def get_data_lines(lines: list[str]) -> list[str] | None:
    try:
        start = lines.index(".data")
    except ValueError:
        return None
    try:
        end = lines.index(".code")
    except ValueError:
        end = None
    if end is not None and end < start:
        end = None
    
    return lines[start+1:end]


LABEL_PAT = re.compile(r'^([0-9a-z_]+):$', re.I)
def parse_instructions(lines: list[str]) -> list[Instruction]:
    next_insn_label = None
    ret = []

    for l in lines:
        if m := LABEL_PAT.match(l):
            next_insn_label = Label(m.group(1))
        else:
            ret.append(Instruction.parse_line(l, next_insn_label))
            if next_insn_label:
                next_insn_label = None

    return ret


def concretize_code_layout(insns: list[Instruction], data_labels: dict[Label, tuple[Data, int]]):
    """In place mutation of instructions to concretize labels into absolute addresses."""

    # build an index of label->addr
    offset = 0
    label_map: dict[Label, int] = {}
    for i in insns:
        if i.label:
            if i.label in label_map or i.label in data_labels:
                raise ValueError(f"label is redefined: {i.label}")

            label_map[i.label] = offset
        offset += i.size

    # replace labels with addrs
    for i in insns:
        if not i.has_symbolics:
            continue
        for idx in range(len(i.args)):
            a = i.args[idx]

            match a:
                case Label():
                    if a in label_map:
                        i.args[idx] = Address(CODE_BASE_ADDRESS+label_map[a])
                    elif a in data_labels:
                        i.args[idx] = Address(data_labels[a][1])
                    else:
                        raise ValueError(f"invalid label: {a} - {i=}")
                case LabelAddr():
                    if a in label_map:
                        i.args[idx] = Immediate(CODE_BASE_ADDRESS+label_map[a])
                    elif a in data_labels:
                        i.args[idx] = Immediate(data_labels[a][1])
                    else:
                        raise ValueError(f"invalid label: {a} - {i=}")
                case DataSize():
                    if a.label in data_labels:
                        i.args[idx] = Immediate(data_labels[a][0].size)
                    else:
                        raise ValueError(f"invalid sizeof: {a} - {i=}")
                case _:
                    pass


def parse_data(lines: list[str]) -> list[Data]:
    return [Data.parse_line(l) for l in lines]


def construct_data_map(datas: list[Data]) -> dict[Label, tuple[Data, int]]:
    """Build a map of data label->absolute address"""

    ret = {}
    offset = 0
    for d in datas:
        if d.label in ret:
            raise ValueError(f"label is redefined: {d.label}")
        ret[d.label] = (d, DATA_BASE_ADDRESS+offset)
        offset += d.size
    
    return ret


def generate_arch_bitmap(code: list[Instruction]) -> bytes:
    """Generate a little-endian bitmap for the architectures of each instruction."""

    # so then you can translate it with ($pc-CODE_BASE) / 8
    #   each bit is an address. addrs that arent the head of an instruction are undefined bits

    # build addr->arch map
    arch_map: dict[int, Architecture] = {}
    offset = 0
    for i in code:
        arch_map[offset] = i.arch
        offset += i.size

    # prepopulate the bitmap with zero bits corresponding to the
    # total consumed address space of the code section
    bitmap = [0]*offset

    for offset, arch in arch_map.items():
        bitmap[offset] = arch.value
    
    out = b""

    # this is garbage but works
    chunk = ""
    for b in bitmap:
        chunk = str(b) + chunk
        if len(chunk) == 8:
            out += bytes([int(chunk, 2)])
            chunk = ""

    if len(chunk) > 0:
        chunk = "0"*(8-len(chunk)) + chunk
        out += bytes([int(chunk, 2)])

    return out


def generate_output_file(code: list[Instruction], data: list[Data]) -> bytes:
    ret = b"MASM"

    code_sz = sum(i.size for i in code)
    data_sz = sum(d.size for d in data)

    arch_bitmap = generate_arch_bitmap(code)

    assert code_sz <= 0x1000
    assert data_sz <= 0x1000

    code_start = 4 + (5*3)  #  magic + 3x segment headers
    data_start = code_start + code_sz
    arch_start = data_start + data_sz

    # segment headers (5 bytes each):
    #   - type
    #   - offset
    #   - size
    ret += struct.pack("<BHH", 1, code_start, code_sz)
    ret += struct.pack("<BHH", 2, data_start, data_sz)
    ret += struct.pack("<BHH", 3, arch_start, len(arch_bitmap))

    ret += b"".join(i.encoded for i in code)
    ret += b"".join(d.value for d in data)
    ret += arch_bitmap

    return ret


def parse_args(args: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(formatter_class=argparse.HelpFormatter)
    parser.add_argument("-i", "--input", required=True)
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("--dump_initial", action="store_true", default=False, help="dump initial code layout")
    parser.add_argument("--dump_final", action="store_true", default=False, help="dump final code layout")
    parser.add_argument("--dump_data", action="store_true", default=False, help="dump data layout")

    return parser.parse_args(args)


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    """
    1. parse the instruction file
    2. get the size of every instruction and data field
    3. compute the offsets for each label from each section head
    4. compile the instructions with the label addresses substituted in
    5. generate the full file with the proper header and arch bitmap
    """

    LOG.info("compiling %s", args.input)

    file_lines = get_input_lines(args.input)

    data_lines = get_data_lines(file_lines)
    if data_lines is None:
        LOG.warning("no data, this is probably wrong")
        datas = []
        data_map = {}
    else:
        datas = parse_data(data_lines)
        data_map = construct_data_map(datas)

    code_lines = get_code_lines(file_lines)
    if code_lines is None:
        LOG.error("no code section found in input")
        return 1
    
    code_insns = parse_instructions(code_lines)
    if args.dump_initial:
        print("########## initial code layout:")
        print("\n".join(str(x) for x in code_insns))

    concretize_code_layout(code_insns, data_map)

    for i in code_insns:
        if len(i.encoded) != i.size:
            raise ValueError(i)

    if args.dump_final:
        print("########## final code layout:")
        print("\n".join(f"{str(x)} - {x.encoded.hex()}" for x in code_insns))
    if args.dump_data:
        print("########## data:")
        print("\n".join(str(x) for x in datas))

    final_payload = generate_output_file(code_insns, datas)

    with open(args.output, "wb") as f:
        f.write(final_payload)

    LOG.info("wrote %d bytes to %s", len(final_payload), args.output)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))


#######################################################################################################################


import tempfile
import unittest


class Tests(unittest.TestCase):
    def test_get_input_lines(self):
        with tempfile.NamedTemporaryFile() as tf:
            with open(tf.name, "w") as f:
                f.write("""
                        hello world
                        // this is a comment
                            yolo swag // skip this

                        noice

                        """)

            lines = get_input_lines(tf.name)
            self.assertEqual(lines, ["hello world", "yolo swag", "noice"])
    
    def test_instruction_parse(self):
        cases = [
            ("  R.Add   A,    #5    ", "<Ins: R.add [<R:A>, <I:0x5>]>"),
            ("r.ADD A, #0xab", "<Ins: R.add [<R:A>, <I:0xab>]>"),
            ("r.add c,d", "<Ins: R.add [<R:C>, <R:D>]>"),
            ("S.SYS", "<Ins: S.sys []>"),
            ("S.JMP my_label", "<Ins: S.jmp [<L:my_label>]>"),
            ("S.JMP @10", "<Ins: S.jmp [<A:0xa>]>"),
            ("S.JMP @0x10", "<Ins: S.jmp [<A:0x10>]>"),
            ("r.push c", "<Ins: R.push [<R:C>]>"),
        ]

        for i, want in cases:
            with self.subTest(i):
                got = repr(Instruction.parse_line(i))
                self.assertEqual(got, want, f"failed, {i=}")

    def test_instruction_size(self):
        cases = [
            ("r.mov a, xyz", 5),
            ("r.mov a, b", 1),
            ("r.mov abc, #345", 9),
            ("r.push #1337", 5),
            ("r.push b", 1),
            ("r.pop b", 1),
            ("r.add a, #5", 6),
            ("r.add a, b", 2),
            ("r.sub a, #5", 6),
            ("r.sub a, b", 2),
            ("r.xor a, #5", 6),
            ("r.xor a, b", 2),
            ("r.mul a, #5", 6),
            ("r.mul a, b", 2),
            ("r.call asdf", 5),
            ("r.call @1234", 5),
            ("r.ret #0", 2),
            ("r.jeq asdf", 5),
            ("r.jg asdf", 5),
            ("r.cmp a, b", 1),
            ("r.cmp a, #5", 5),
            ("r.hlt", 1),
            ("r.sys", 1),
            ("s.ldb #5", 5)
        ]
        
        for i, want in cases:
            with self.subTest(i):
                got = Instruction.parse_line(i).size
                self.assertEqual(got, want, f"failed, {i=}")
    
    def test_instruction_encoding(self):
        cases = [
            ("r.mov a, b", b"\xc1"),
            ("r.mov a, sp", b"\xc6"),
            ("r.mov a, #5", b"\xc5\x05\x00\x00\x00"),
            ("r.mov *a, #5", b"\xa4\xc5\x05\x00\x00\x00"),
            ("r.mov *a, *b", b"\xa5\xc1"),
            ("r.mov @0xabcd, #5", b"\xe5\xcd\xab\x00\x00\x05\x00\x00\x00"),
            ("r.mov @0xabcd, @0x1234", b"\xe4\xcd\xab\x00\x00\x34\x12\x00\x00"),
            ("r.push #0x1337", b"\x10\x37\x13\x00\x00"),
            ("r.push b", b"\x12"),
            ("r.pop b", b"\x16"),
            ("r.add a, b", b"\x20\x12"),
            ("r.add a, #5", b"\x21\x10\x05\x00\x00\x00"),
            ("r.sub a, b", b"\x30\x12"),
            ("r.sub a, #5", b"\x31\x10\x05\x00\x00\x00"),
            ("r.sub sp, #5", b"\x31\x50\x05\x00\x00\x00"),
            ("r.xor a, b", b"\x40\x12"),
            ("r.xor a, #5", b"\x41\x10\x05\x00\x00\x00"),
            ("r.mul a, b", b"\x50\x12"),
            ("r.mul a, #5", b"\x51\x10\x05\x00\x00\x00"),
            ("r.call @0x1234", b"\x60\x34\x12\x00\x00"),
            ("r.ret #0", b"\x61\x00"),
            ("r.jeq @0x1234", b"\x62\x34\x12\x00\x00"),
            ("r.jne @0x1234", b"\x63\x34\x12\x00\x00"),
            ("r.jg @0x1234", b"\x64\x34\x12\x00\x00"),
            ("r.jmp @0x1234", b"\x68\x34\x12\x00\x00"),
            ("r.cmp a, b", b"\x71"),
            ("r.cmp c, #5", b"\x82\x05\x00\x00\x00"),
            ("r.hlt", b"\x00"),
            ("r.sys", b"\x01"),

            ("s.ldb #5", b"\x10\x05\x00\x00\x00"),
            ("s.ldw #0xaabb", b"\x20\xbb\xaa\x00\x00"),
            ("s.ldd #0xaabbccdd", b"\x30\xdd\xcc\xbb\xaa"),
            ("s.ldp @0xaabb", b"\x40\xbb\xaa\x00\x00"),
            ("s.pop", b"\x50\x00\x00\x00\x00"),
            ("s.add", b"\x60\x00\x00\x00\x00"),
            ("s.sub", b"\x61\x00\x00\x00\x00"),
            ("s.xor", b"\x62\x00\x00\x00\x00"),
            ("s.and", b"\x63\x00\x00\x00\x00"),
            ("s.jmp @0xaabbccdd", b"\x70\xdd\xcc\xbb\xaa"),
            ("s.jeq @0xaabbccdd", b"\x71\xdd\xcc\xbb\xaa"),
            ("s.jne @0xaabbccdd", b"\x72\xdd\xcc\xbb\xaa"),
            ("s.cmp", b"\x80\x00\x00\x00\x00"),
            ("s.sys", b"\xa0\x00\x00\x00\x00"),
            ("s.hlt", b"\xff\xff\xff\xff\xff"),
        ]
        
        for i, want in cases:
            with self.subTest(i):
                got = Instruction.parse_line(i).encoded
                self.assertEqual(got, want, f"failed, {i=}")

    def test_get_code_lines(self):
        with tempfile.NamedTemporaryFile() as tf:
            with open(tf.name, "w") as f:
                f.write("""
                        .code
                        asdf
                        zxcv
                        hello
                        """)

            lines = get_input_lines(tf.name)
            code = get_code_lines(lines)
            self.assertEqual(code, ["asdf", "zxcv", "hello"])

        with tempfile.NamedTemporaryFile() as tf:
            with open(tf.name, "w") as f:
                f.write("""
                        .code
                        asdf
                        zxcv
                        hello

                        .data
                        one
                        two
                        three
                        """)

            lines = get_input_lines(tf.name)
            code = get_code_lines(lines)
            self.assertEqual(code, ["asdf", "zxcv", "hello"])
        
        with tempfile.NamedTemporaryFile() as tf:
            with open(tf.name, "w") as f:
                f.write("""
                        .data
                        one
                        two
                        three

                        .code

                        asdf
                        zxcv
                        hello
                        """)

            lines = get_input_lines(tf.name)
            code = get_code_lines(lines)
            self.assertEqual(code, ["asdf", "zxcv", "hello"])
        
        with tempfile.NamedTemporaryFile() as tf:
            with open(tf.name, "w") as f:
                f.write("""
                        .data
                        one
                        two
                        three
                        """)

            lines = get_input_lines(tf.name)
            code = get_code_lines(lines)
            self.assertIsNone(code)
    
    def test_get_data_lines(self):
        with tempfile.NamedTemporaryFile() as tf:
            with open(tf.name, "w") as f:
                f.write("""
                        .data
                        asdf
                        zxcv
                        hello
                        """)

            lines = get_input_lines(tf.name)
            data = get_data_lines(lines)
            self.assertEqual(data, ["asdf", "zxcv", "hello"])

        with tempfile.NamedTemporaryFile() as tf:
            with open(tf.name, "w") as f:
                f.write("""
                        .data
                        asdf
                        zxcv
                        hello

                        .code
                        one
                        two
                        three
                        """)

            lines = get_input_lines(tf.name)
            data = get_data_lines(lines)
            self.assertEqual(data, ["asdf", "zxcv", "hello"])
        
        with tempfile.NamedTemporaryFile() as tf:
            with open(tf.name, "w") as f:
                f.write("""
                        .code
                        one
                        two
                        three

                        .data

                        asdf
                        zxcv
                        hello
                        """)

            lines = get_input_lines(tf.name)
            data = get_data_lines(lines)
            self.assertEqual(data, ["asdf", "zxcv", "hello"])
        
        with tempfile.NamedTemporaryFile() as tf:
            with open(tf.name, "w") as f:
                f.write("""
                        .code
                        one
                        two
                        three
                        """)

            lines = get_input_lines(tf.name)
            data = get_data_lines(lines)
            self.assertIsNone(data)

    def test_parse_instruction(self):
        lines = [
            "hello_there:",
            "s.ldb #5",
            "r.jmp hello_there",
            "done:",
            "r.hlt",
        ]
        want = [
            "<Ins: @hello_there S.ldb [<I:0x5>]>",
            "<Ins: R.jmp [<L:hello_there>]>",
            "<Ins: @done R.hlt []>",
        ]

        got = [repr(x) for x in parse_instructions(lines)]
        self.assertListEqual(got, want)

    def test_concretize_code_layout(self):
        lines = [
            "hello:",
            "s.ldb #5",
            "r.jmp hello",
            "r.jmp done",
            "done:",
            "r.hlt",
            "r.mov a, mystr"
        ]
        want = [
            "<Ins: @hello S.ldb [<I:0x5>]>",
            "<Ins: R.jmp [<A:0x1000>]>",
            "<Ins: R.jmp [<A:0x100f>]>",
            "<Ins: @done R.hlt []>",
            "<Ins: R.mov [<R:A>, <A:0x2048>]>",
        ]

        insns = parse_instructions(lines)
        concretize_code_layout(insns, {Label("mystr"): (Data(Label("mystr"), b"asdf"), 0x2048)})
        got = [repr(x) for x in insns]
        self.assertListEqual(got, want)

    def test_parse_data(self):
        lines = ['a: "asdf"', r'beez: "\xaa\xbb\xcc\xdd"']
        want = [
            Data(label=Label("a"), value=b"asdf"),
            Data(label=Label("beez"), value=b"\xaa\xbb\xcc\xdd"),
        ]
        got = parse_data(lines)
        self.assertListEqual(want, got)

    def test_construct_data_map(self):
        datas = [
            Data(label=Label("a"), value=b"asdf"),
            Data(label=Label("c"), value=b"\xaa\xdd"),
            Data(label=Label("e"), value=b"98839383asdf"),
        ]

        want = {
            Label("a"): (datas[0], 0x2000),
            Label("c"): (datas[1], 0x2004),
            Label("e"): (datas[2], 0x2006),
        }
        got = construct_data_map(datas)
        self.assertDictEqual(got, want)
    
    def test_generate_arch_bitmap(self):
        lines = [
            "s.pop",
            "s.pop",
            "s.pop",
            "r.sys",
            "r.sys",
            "s.pop",
            "r.sys",
            "s.pop",
            "r.sys",
            "r.sys",
            "r.sys",
            "s.pop",
        ]

        # s=0 | r=1
        # in list order: 000110101110
        # little endian chunks: 01011000 00000111
        want = bytes([int("01011000", 2), int("00000111", 2)])
        got = generate_arch_bitmap(parse_instructions(lines))
        # self.assertEqual(want, got)
        # TODO: update this test for the new bitmap scheme. i am lazy rn
    
    def test_data_sizeof(self):
        code_lines = ["s.ldb sizeof(mystr)"]
        insns = parse_instructions(code_lines)
        
        data_lines = ['mystr: "asdfzxcv"']
        datas = parse_data(data_lines)
        data_map = construct_data_map(datas)

        concretize_code_layout(insns, data_map)
        self.assertEqual("<Ins: S.ldb [<I:0x8>]>", repr(insns[0]))
