# Copyright 2024 Google LLC
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
from flag import flag

def menu():
  print("1. Reset")
  print("2. Show circuit")
  print("3. Add new gate")
  print("4. Send to factory and test")
  print("5. Quit")
  return int(input())

def check_validity(gates):
  global_inputs = ["A", "B", "C"]
  global_outputs = ["S", "Cout"]

  all_inputs = global_outputs + [g[1] for g in gates] + [g[2] for g in gates]
  all_outputs = global_inputs + [g[0] for g in gates]

  for g in gates:
    o, i1, i2 = g
    if o in global_inputs:
      return "Invalid gate %s: trying to output to the circuit input" % str(g)
    if i1 in global_outputs or i2 in global_outputs:
      return "Invalid gate %s: trying to input from the circuit output" % str(g)

  for i in all_inputs:
    if i not in all_outputs:
      return "Error: %s not connected" % i

  return None

def init_state(gates):
  state = {}
  for o, i1, i2 in gates:
    state[o] = 0
    if o[-1] == '^':
      state[o] = 1
  return state

def propagate(state, gates):
  for i in range(50):
    new_state = state.copy()
    for o, i1, i2 in gates:
      new_state[o] = nand(state[i1], state[i2])

    if state == new_state:
      return state

    state = new_state

  raise Exception("Error: circuit is too slow to converge!")

testcases = [
    [   #A  B  C  S  Cout
        (0, 0, 0, 0, 0),
        (0, 0, 1, 1, 0),
        (0, 1, 0, 1, 0),
        (0, 1, 1, 0, 1),
        (1, 0, 0, 1, 0),
        (1, 0, 1, 0, 1),
        (1, 1, 0, 0, 1),
        (1, 1, 1, 1, 1),
    ] * 2,
    [
        (0, 0, 0, 0, 0), (0, 0, 0, 0, 0), (0, 0, 1, 1, 0), (0, 0, 0, 0, 0), (0, 1, 0, 1, 0), (0, 0, 0, 0, 0), (0, 1, 1, 0, 1), (0, 0, 0, 0, 0),
        (1, 0, 0, 1, 0), (0, 0, 0, 0, 0), (1, 0, 1, 0, 1), (0, 0, 0, 0, 0), (1, 1, 0, 0, 1), (0, 0, 0, 0, 0), (1, 1, 1, 1, 1), (0, 0, 1, 1, 0),
        (0, 0, 1, 1, 0), (0, 1, 0, 1, 0), (0, 0, 1, 1, 0), (0, 1, 1, 0, 1), (0, 0, 1, 1, 0), (1, 0, 0, 1, 0), (0, 0, 1, 1, 0), (1, 0, 1, 0, 1),
        (0, 0, 1, 1, 0), (1, 1, 0, 0, 1), (0, 0, 1, 1, 0), (1, 1, 1, 1, 1), (0, 1, 0, 1, 0), (0, 1, 0, 1, 0), (0, 1, 1, 0, 1), (0, 1, 0, 1, 0),
        (1, 0, 0, 1, 0), (0, 1, 0, 1, 0), (1, 0, 1, 0, 1), (0, 1, 0, 1, 0), (1, 1, 0, 0, 1), (0, 1, 0, 1, 0), (1, 1, 1, 1, 1), (0, 1, 1, 0, 1),
        (0, 1, 1, 0, 1), (1, 0, 0, 1, 0), (0, 1, 1, 0, 1), (1, 0, 1, 0, 1), (0, 1, 1, 0, 1), (1, 1, 0, 0, 1), (0, 1, 1, 0, 1), (1, 1, 1, 1, 1),
        (1, 0, 0, 1, 0), (1, 0, 0, 1, 0), (1, 0, 1, 0, 1), (1, 0, 0, 1, 0), (1, 1, 0, 0, 1), (1, 0, 0, 1, 0), (1, 1, 1, 1, 1), (1, 0, 1, 0, 1),
        (1, 0, 1, 0, 1), (1, 1, 0, 0, 1), (1, 0, 1, 0, 1), (1, 1, 1, 1, 1), (1, 1, 0, 0, 1), (1, 1, 0, 0, 1), (1, 1, 1, 1, 1), (1, 1, 1, 1, 1),
    ] * 2
]

def nand(a, b):
  return 1 - (a and b)

def check_adder(gates):
  try:
    for tnum, tc in enumerate(testcases):
      for startpoint in range(len(tc)):
        print("Running test %d-%d..." % (tnum, startpoint))
        testcase = tc[startpoint:]
        state = init_state(gates)

        for a, b, c, s, cout in testcase:
          state["A"] = a
          state["B"] = b
          state["C"] = c
          state = propagate(state, gates)

          ss, sc = state["S"], state["Cout"]
          if (ss, sc) != (s, cout):
            return "Error: Wrong output for %s - expected %s, got %s" % ((a, b, c), (s, cout), (ss, sc))

  except Exception as e:
    return repr(e)

  return None

def run_cpu(eight_bit_adder):
  state = init_state(eight_bit_adder)
  for i in range(8):
    state["bit%d_A" % i] = 0
    state["bit%d_B" % i] = 0
  state["bit0_C"] = 0
  state = propagate(state, eight_bit_adder)

  regs = {"r0": 0, "r1": 0, "r2": 0, "r3": 0, "r4": 0, "r5": 0, "r6": 0, "r7": 0}
  pc = 0
  mem = [0] * 256
  # Secret key for other cryptographic tasks.
  for i, c in enumerate(flag):
    mem[i + 128] = ord(c)

  program = """
ldi r0, 0
ldi r1, 0
ldi r2, 60
ldi r3, 10
ldi r5, 1
read r4
store r1, r4
jeq r4, r3, 11
add r0, r5
add r1, r5
jl r0, r2, 5
ldi r1, 0
ldi r3, 3
load r4, r1
add r4, r3
ldi r2, 64
add r2, r1
store r2, r4
add r1, r5
jl r1, r0, 13
ldi r1, 0
ldi r2, 64
add r2, r1
load r2, r2
out r2
add r1, r5
jl r1, r0, 21
  """.strip().splitlines()

  for i in range(100000):
    if pc >= len(program): break
    op = program[pc]
    pc += 1
    args = op.split(";")[0].replace(",", "").split()
    # A very simple instruction set, for cryptographic purposes only.
    if args[0] == "ldi":
      regs[args[1]] = int(args[2])
    elif args[0] == "read":
      regs[args[1]] = ord((input("CPU is awaiting input character...\n") + "\n")[0]) & 255
    elif args[0] == "out":
      print("CPU outputs: %c" % chr(regs[args[1]]))
    elif args[0] == "store":
      mem[regs[args[1]]] = regs[args[2]]
    elif args[0] == "load":
      regs[args[1]] = mem[regs[args[2]]]
    elif args[0] == "jeq":
      if regs[args[1]] == regs[args[2]]:
        pc = int(args[3])
    elif args[0] == "jl":
      if regs[args[1]] < regs[args[2]]:
        pc = int(args[3])
    elif args[0] == "add":
      # Hardware crypto acceleration:
      A = regs[args[1]]
      B = regs[args[2]]
      state["bit0_C"] = 0
      for j in range(8):
        state["bit%d_A" % j] = (A >> j) & 1
        state["bit%d_B" % j] = (B >> j) & 1
      state = propagate(state, eight_bit_adder)
      S = 0
      for j in range(8):
        S |= state["bit%d_S" % j] << j
      regs[args[1]] = S
    else:
      raise Exception("Unknown opcode %s" % args[0])

  return None

def main():
  print("""
 .----------------------------------------------------------------.
| .--------------------------------------------------------------. |
| |  ____  ____   _____  _____    _______   _____   ____    ____ | |
| | |_   ||   _| |_   _||_   _|  /  ___  | |_   _| |_   \  /   _|| |
| |   | |__| |     | | /\ | |   |  (__ \_|   | |     |   \/   |  | |
| |   |  __  |     | |/  \| |    '.___`-.    | |     | |\  /| |  | |
| |  _| |  | |_    |   /\   |   |`\____) |  _| |_   _| |_\/_| |_ | |
| | |____||____|   |__/  \__|   |_______.' |_____| |_____||_____|| |
| |                                                              | |
| '--------------------------------------------------------------' |
 '----------------------------------------------------------------'
""")
  print("")
  print("Welcome to G.U.G.L. hardware design and testing software.")
  print("We have nearly finished our newest CPU, but we are still")
  print("missing a critical component.")
  print("")
  print("We need you to make us a full adder out of NAND gates:")
  print("Inputs: A, B, C")
  print("Outputs: S, Cout")

  gates = []
  while True:
    choice = menu()
    if choice == 1:
      gates = []
    elif choice == 2:
      for gate in gates:
        print("%s = NAND(%s, %s)" % gate)
    elif choice == 3:
      print("Send three strings identifying one output and two inputs")
      out, i1, i2 = input().split()
      gates.append((out, i1, i2))
      if len(gates) > 250:
        print("That's way too many gates! How hard could an adder be?!")
        break
    elif choice == 4:
      err = check_validity(gates)
      if err:
        print(err)
        continue
      print("Circuit compiled correctly, sending to factory...")
      err = check_adder(gates)
      if err:
        print(err)
        continue
      print("Circuit passed exhaustive testing, integrating with the CPU...")
      eight_bit_adder = []
      for i in range(8):
        for o, i1, i2 in gates:
          if o == "Cout":
            # Join carry output and input.
            eight_bit_adder.append(("bit%d_%s" % (i+1, "C"), "bit%d_%s" % (i, i1), "bit%d_%s" % (i, i2)))
          else:
            eight_bit_adder.append(("bit%d_%s" % (i, o), "bit%d_%s" % (i, i1), "bit%d_%s" % (i, i2)))

      print("Deploying military-grade encryption program running on the synthesized CPU...")

      try:
        run_cpu(eight_bit_adder)
      except Exception as e:
        print(repr(e))
        break

    elif choice == 5:
      print("Bye!")
      break


if __name__ == "__main__":
  main()
