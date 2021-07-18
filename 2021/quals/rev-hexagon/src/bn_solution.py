#!/usr/bin/env python3
#
# Copyright (C) 2020 Google LLC
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import argparse
import copy
import sys
import struct
import binascii
import pprint
import functools
import z3

try:
  import binaryninja as binja
except ImportError:
  print('Failed to import binaryninja Python API')
  print('Install API using ${BN_INSTALL_DIR}/scripts/install_api.py')
  sys.exit(1)

# Must be 8 bytes long.
FLAG = b'IDigVLIW'
MASK_KEY = 0x28


class FeistelNetwork(object):

  def __init__(self, key_rounds):
    self.key_rounds = copy.copy(key_rounds)

  def CipherFunction(self, key, inp):
    return key ^ inp

  def Encrypt(self, plaintext):
    L, R = struct.unpack('<LL', plaintext)

    for ki in self.key_rounds:
      L, R = R, L ^ self.CipherFunction(ki, R)

    return struct.pack('<LL', R, L)

  def Decrypt(self, cipherptext):
    L, R = struct.unpack('<LL', cipherptext)

    for ki in reversed(self.key_rounds):
      L, R = R, L ^ self.CipherFunction(ki, R)

    return struct.pack('<LL', R, L)


def CreateBitVec(ssa_var):
  # All z3 variables are either 32 bit vectors, or booleans.
  assert (isinstance(ssa_var, binja.SSAVariable))
  return z3.BitVec('{}#{}'.format(ssa_var.var.name, ssa_var.version), 32)


def CanonicalVarForBranch(branch_idx):
  return z3.Bool('IF_{0}'.format(branch_idx))


# Imported from https://github.com/trailofbits/binjascripts/blob/master/find_heartbleed/bnilvisitor.py
class BNILVisitor(object):

  def __init__(self, **kw):
    super(BNILVisitor, self).__init__()

  def visit(self, expression):
    method_name = 'visit_{}'.format(expression.operation.name)
    if hasattr(self, method_name):
      print(expression.instr_index, expression.operation.name, expression)
      value = getattr(self, method_name)(expression)
    else:
      print('missing ', method_name)
      assert (0)
      value = None
    return value


# Models the data flow dependencies between the function's return value
# and its arguments.
# Inspired by https://github.com/trailofbits/binjascripts/blob/master/find_heartbleed/find_heartbleed.py
class FunctionModeler(BNILVisitor):

  def __init__(self, func):
    super(FunctionModeler, self).__init__()
    assert (isinstance(func, binja.MediumLevelILFunction))
    self.solver = z3.Solver()
    self.visited = set()
    self.to_visit = list()
    self.func = func

  def FindReturnInstruction(self):
    ops = list(
        filter(lambda i: i.operation == binja.MediumLevelILOperation.MLIL_RET,
               self.func.instructions))
    assert (len(ops) == 1)
    return ops.pop()

  def FindReturnVariable(self):
    ret = self.FindReturnInstruction()
    assert (len(ret.operands) == 1)
    assert (len(ret.operands[0]) == 1)
    assert (len(ret.operands[0][0].vars_read) == 1)
    return ret.operands[0][0].vars_read[0]

  def BuildModel(self):
    # Start with the return value, and work back through its dependencies.
    ret_var = self.FindReturnVariable()
    var_def = self.func.get_ssa_var_definition(ret_var)

    # Visit statements that our variable directly depends on
    self.to_visit.append(var_def)

    while self.to_visit:
      idx = self.to_visit.pop()
      self.visit(self.func[idx])

  def VariableControlFlowDependency(self, var):
    assert (isinstance(var, binja.SSAVariable))
    var_def = self.func.get_ssa_var_definition(var)
    if not var_def.branch_dependence:
      # No dependency.
      return z3.BoolVal(True)

    assert (len(var_def.branch_dependence) == 1)
    branch_idx, branch_type = next(iter(var_def.branch_dependence.items()))
    canon_var = CanonicalVarForBranch(branch_idx)
    if branch_type == binja.ILBranchDependence.TrueBranchDependent:
      return canon_var
    else:
      return z3.Not(canon_var)

  # X#3 = phi(X#1, X#2)
  #
  # A naive model does not include control flow dependencies:
  #  Or(And(X#3 == X#1),
  #     And(X#3 == X#2))
  #
  # A correct model includes control flow dependencies. Two options:
  # 1. X#1, X#2 updated in separate if-else branches:
  #    if (cond) {
  #      X#1 = ...
  #    } else {
  #      X#2 = ...
  #    }
  #
  #  Or(And(X#3 == X#1, IF_2),
  #     And(X#3 == X#2, Not(IF_2))),
  #
  # 2. Only one variable is updated in an if or else branch:
  #    X#1 = ...
  #    if (cond) {
  #      X#2 = ...
  #    }
  #  In this case we also model (X#3 == X#1) together with !cond:
  #  Or(And(X#3 == X#1, Not(IF_2)),
  #     And(X#3 == X#2, IF_2)),
  def visit_MLIL_VAR_PHI(self, expr):
    # For simplicity assume phi statements do not have control flow dependencies.
    assert (not expr.branch_dependence)
    # Again, for simplicity, assume phi statements only have two input sources.
    assert (len(expr.src) == 2)

    # Visit source vars definitions.
    for var in expr.src:
      var_def = self.func.get_ssa_var_definition(var)
      if var not in self.visited:
        self.to_visit.append(var_def)

    phi_srcs = [CreateBitVec(var) for var in expr.src]
    phi_deps = [self.VariableControlFlowDependency(var) for var in expr.src]

    # If only one of phi's sources has a control flow dependency,
    # model the other with the negation of the dependency.
    # See function comment above.
    if z3.is_true(phi_deps[0]) and not z3.is_true(phi_deps[1]):
      phi_deps[0] = z3.Not(phi_deps[1])
    elif not z3.is_true(phi_deps[0]) and z3.is_true(phi_deps[1]):
      phi_deps[1] = z3.Not(phi_deps[0])

    dest = CreateBitVec(expr.dest)
    phi_expr = functools.reduce(
        lambda i, j: z3.Or(i, j),
        [z3.And((dest == src), dep) for (src, dep) in zip(phi_srcs, phi_deps)])
    self.solver.add(phi_expr)

    self.visited.add(expr.dest)

  def visit_MLIL_SET_VAR_SSA(self, expr):
    dest = CreateBitVec(expr.dest)
    src = self.visit(expr.src)
    if isinstance(src, z3.BoolRef):
      assert (expr.size == 1)
      # Replace z3 boolean with bit vector.
      src = z3.If(src, z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
    else:
      assert (isinstance(src, z3.BitVecRef))

    if expr.branch_dependence:
      assert (len(expr.branch_dependence) == 1)
      branch_idx, branch_type = next(iter(expr.branch_dependence.items()))
      branch = self.func[branch_idx]
      if branch not in self.visited:
        self.to_visit.append(branch)

      canon_var = CanonicalVarForBranch(branch_idx)
      if branch_type == binja.ILBranchDependence.TrueBranchDependent:
        self.solver.add(z3.If(canon_var, (dest == src), z3.BoolVal(True)))
      else:
        self.solver.add(
            z3.If(z3.Not(canon_var), (dest == src), z3.BoolVal(True)))

    else:
      # No control flow dependencies.
      self.solver.add(dest == src)

    self.visited.add(expr.dest)

  def visit_MLIL_VAR_SSA(self, expr):
    # Visit source var definitions.
    if expr.src not in self.visited:
      var_def = expr.function.get_ssa_var_definition(expr.src)
      if var_def is not None:
        self.to_visit.append(var_def)

    return CreateBitVec(expr.src)

  def visit_MLIL_SUB(self, expr):
    left = self.visit(expr.left)
    right = self.visit(expr.right)
    assert (None not in (left, right))
    return left - right

  def visit_MLIL_ADD(self, expr):
    left = self.visit(expr.left)
    right = self.visit(expr.right)
    assert (None not in (left, right))
    return left + right

  def visit_MLIL_XOR(self, expr):
    left = self.visit(expr.left)
    right = self.visit(expr.right)
    assert (None not in (left, right))
    return left ^ right

  def visit_MLIL_CMP_E(self, expr):
    left = self.visit(expr.left)
    right = self.visit(expr.right)
    assert (None not in (left, right))
    return left == right

  def visit_MLIL_CMP_NE(self, expr):
    left = self.visit(expr.left)
    right = self.visit(expr.right)
    assert (None not in (left, right))
    return left != right

  def visit_MLIL_AND(self, expr):
    left = self.visit(expr.left)
    right = self.visit(expr.right)
    assert (None not in (left, right))
    return left & right

  def visit_MLIL_CONST(self, expr):
    assert (expr.size in [1, 4])
    return z3.BitVecVal(expr.constant, 32)

  def visit_MLIL_IF(self, expr):
    cond = self.visit(expr.condition)
    canon_var = CanonicalVarForBranch(expr.instr_index)

    if isinstance(cond, z3.BoolRef):
      self.solver.add(cond == canon_var)
    else:
      assert (isinstance(cond, z3.BitVecRef))
      self.solver.add((cond > 0) == canon_var)

    self.visited.add(expr)


class Analyzer:

  def __init__(self, filename):
    self.bv = binja.BinaryViewType.get_view_of_file(filename)
    self.models = {}

  def visit(self, expression):
    method_name = 'visit_{}'.format(expression.operation.name)
    if hasattr(self, method_name):
      value = getattr(self, method_name)(expression)
    else:
      value = None
    return value

  def FindFunctionByName(self, name):
    sym = self.bv.get_symbol_by_raw_name(name)
    return self.bv.get_function_at(sym.address)

  def ModelHexFunctions(self):
    for i in [1, 2, 3, 4, 5, 6]:
      name = 'hex%d' % i
      func = self.FindFunctionByName(name)
      mlil = func.medium_level_il.ssa_form
      self.models[name] = FunctionModeler(mlil)
      self.models[name].BuildModel()

  def GetHexFuncCallArguments(self, name):
    func = self.FindFunctionByName(name)
    callers = self.bv.get_code_refs(func.start)
    assert (len(callers) == 1)
    ref = callers.pop()
    call = ref.function.get_low_level_il_at(
        ref.address).medium_level_il.ssa_form
    assert (call.params[0].operation == binja.MediumLevelILOperation.MLIL_CONST)
    assert (call.params[1].operation == binja.MediumLevelILOperation.MLIL_CONST)
    r0 = call.params[0].value.value
    r1 = call.params[1].value.value
    return (r0, r1)

  def EvaluateHexFunction(self, modeler, arg1, arg2):
    try:
      modeler.solver.push()

      modeler.solver.add(z3.BitVec('arg1#0', 32) == arg1)
      modeler.solver.add(z3.BitVec('arg2#0', 32) == arg2)
      print(modeler.solver)
      assert (modeler.solver.check() != z3.unsat)

      ret_var = modeler.FindReturnVariable()
      ret = CreateBitVec(ret_var)
      # pprint.pprint(modeler.solver.sexpr())
      m = modeler.solver.model()
      print(m)
      return m.eval(ret).as_long()
    finally:
      modeler.solver.pop()

  def EvaluateInvertedHexFunction(self, modeler, arg2, ret_val):
    try:
      modeler.solver.push()

      ret_var = modeler.FindReturnVariable()
      ret = CreateBitVec(ret_var)
      modeler.solver.add(ret == ret_val)
      modeler.solver.add(z3.BitVec('arg2#0', 32) == arg2)
      print(modeler.solver)
      assert (modeler.solver.check() != z3.unsat)

      arg1 = z3.BitVec('arg1#0', 32)
      m = modeler.solver.model()
      print(m)
      return m.eval(arg1).as_long()
    finally:
      modeler.solver.pop()

  def ComputeKeyRound(self, name):
    r0, r1 = self.GetHexFuncCallArguments(name)
    return self.EvaluateHexFunction(self.models[name], r0, r1)

  def TransformFlag(self, inp):
    r2, r3 = struct.unpack('<LL', inp)
    # hex1()
    r2 = self.EvaluateHexFunction(self.models['hex1'], r2, 1) ^ 1869029418
    # hex2()
    r3 = self.EvaluateHexFunction(self.models['hex2'], r3, 6) ^ 1701603183
    return struct.pack('<LL', r2, r3)

  def UntransformFlag(self, inp):
    r2, r3 = struct.unpack('<LL', inp)
    # Inverted hex1()
    r2 = self.EvaluateInvertedHexFunction(self.models['hex1'], 1,
                                          r2 ^ 1869029418)
    # Inverted hex2()
    r3 = self.EvaluateInvertedHexFunction(self.models['hex2'], 6,
                                          r3 ^ 1701603183)
    return struct.pack('<LL', r2, r3)

  def ComputeFeistelKeyValues(self):
    kr = []
    for i in [3, 4, 5, 6]:
      name = 'hex%d' % i
      kr.append(self.ComputeKeyRound(name))
    return kr

  def ExtractTargetCiphertext(self):
    sym = self.bv.get_symbol_by_raw_name('target')
    ct = [0] * 8
    for (i, b) in enumerate(self.bv.read(sym.address, len(ct))):
      ct[i] = bytes([(MASK_KEY + i) ^ b])
    return b''.join(ct)


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument(
      '-s',
      '--solve',
      default=False,
      action='store_true',
      help='Find correct solution, check it matches hardcoded flag')
  parser.add_argument(
      '-r',
      '--reflag',
      default=False,
      action='store_true',
      help='Print target ciphertext for the hardcoded flag')
  parser.add_argument(
      'input', metavar='INPUT', type=str, help='Challenge binary to disasm')
  args = parser.parse_args()

  print('Analyzing {0}'.format(args.input))
  binja.log.log_to_stdout(True)
  analyzer = Analyzer(args.input)

  # Model bijective hex functions. With these models we can:
  #  * Evaluate the function's return value for a given input.
  #  * Invert the function, return the input for a given output.
  analyzer.ModelHexFunctions()

  # Extract key rounds.
  key_rounds = analyzer.ComputeFeistelKeyValues()
  network = FeistelNetwork(key_rounds)

  if args.solve:
    # Extract ciphertext.
    ct = analyzer.ExtractTargetCiphertext()
    # Swap left/right.
    L, R = struct.unpack('<LL', ct)
    ct = struct.pack('<LL', R, L)

    # Find solution.
    pt = network.Decrypt(ct)
    sol = analyzer.UntransformFlag(pt)

    assert (sol == FLAG)
    print('Solve completed successfully!')

  if args.reflag:
    pt = analyzer.TransformFlag(FLAG)
    ct = network.Encrypt(pt)
    # Swap left/right.
    L, R = struct.unpack('<LL', ct)
    ct = struct.pack('<LL', R, L)
    print('target:')
    for (i, b) in enumerate(ct):
      print('.byte 0x{0:x} ^ 0x{1:x}'.format(MASK_KEY + i, b))


if __name__ == '__main__':
  main()
