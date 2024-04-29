# Copyright 2023 Google LLC
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
import logging
from ctypes import c_uint8
from typing import Optional


class Interpreter:
    def __init__(self, instructions: bytes, max_steps=100000):
        self.stopped = False

        self.instructions = instructions
        self.max_instructions = max_steps

        self.pc = 0
        self.dp = 0
        self.data = bytearray(b'\0')
        self.res = []
        self.executed_instructions = 0

        self.jmps = {}

        self.order_ptr = 0
        self.order = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

    def parse_jumps(self):
        jumps = {}
        locations = []
        for i in range(len(self.instructions)):
            if self.instructions[i] == ord('['):
                locations.append(i)
            elif self.instructions[i] == ord(']'):
                try:
                    l = locations.pop()
                except SyntaxError:
                    # syntax error, there's no matching bracket
                    self.instructions[i] = b'!'
                    continue
                except Exception as e:
                    logging.critical(f"Failed to parse: {e}")
                    continue
                jumps[i] = l
                jumps[l] = i
        return jumps

    def start(self):
        logging.info(f"current order: {self.order}")
        self.jmps = self.parse_jumps()

        # while not self.stopped:
        #     a = self.step()
        #
        # return self.res

    def execute_until_return(self):
        if self.stopped:
            return
        a = self.step()
        if self.executed_instructions >= self.max_instructions:
            logging.critical("Exceeded max number of steps")
        while not self.stopped and a is None and self.executed_instructions < \
                self.max_instructions:
            try:
                a = self.step()
            except Exception as e:
                logging.critical(f"Execution error: {e}")
                self.stopped = True
        return a

    def execute_until_end(self):
        a = self.step()
        if self.executed_instructions >= self.max_instructions:
            logging.critical("Exceeded max number of steps")
        while not self.stopped and self.executed_instructions < \
                self.max_instructions:
            try:
                self.step()
            except Exception as e:
                logging.critical(f"Execution error: {e}")
                self.stopped = True
        return self.res

    def step(self) -> Optional[int]:
        # print(self.data)
        if self.stopped:
            return
        self.executed_instructions += 1
        op = self.instructions[self.pc]
        # print(chr(op))

        # print(f"Data: {self.data}, DP: {self.dp}, OP: {chr(op)}, PC: {self.pc}")
        retval = None
        match op:
            case 33:  # !
                # Addition: Exit on missing brackets
                self.stopped = True
            case 62:  # >
                # Increment the data pointer by one (to point to the next cell to the
                # right).
                self.dp += 1
                if len(self.data) <= self.dp:
                    self.data += b'\0'
            case 60:  # <
                # Decrement the data pointer by one (to point to the next cell to the
                # left).
                self.dp = max(0, self.dp - 1)
            case 43:  # +
                # Increment the byte at the data pointer by one.
                self.data[self.dp] = c_uint8(self.data[self.dp] + 1).value
            case 45:  # -
                # Decrement the byte at the data pointer by one.
                self.data[self.dp] = c_uint8(self.data[self.dp] - 1).value
            case 46:  # .
                # Output the byte at the data pointer.
                logging.debug("%c" % (self.data[self.dp]))
                self.res.append(self.data[self.dp])
                retval = self.data[self.dp]
            case 44:  # ,
                # Accept one byte of input, storing its value in the byte at the data
                # pointer.
                if self.order_ptr < len(self.order):
                    self.data[self.dp] = self.order[self.order_ptr]
                else:
                    self.data[self.dp] = 0xFF
                self.order_ptr += 1
            case 91:  # [
                # If the byte at the data pointer is zero, then instead of moving the
                # instruction pointer forward to the next command, jump it forward to
                # the command after the matching ] command.
                if self.pc in self.jmps:
                    self.pc = self.jmps[self.pc] if self.data[self.dp] == 0 else self.pc + 1
                return
            case 93:  # ]
                # If the byte at the data pointer is nonzero, then instead of moving
                # the instruction pointer forward to the next command, jump it back
                # to the command after the matching [ command.[a]
                if self.pc in self.jmps:
                    self.pc = self.jmps[self.pc] if self.data[self.dp] != 0 else self.pc + 1
                return
            case other:
                logging.critical(f"Unknown op: {other}")

        self.pc += 1
        if self.pc == len(self.instructions):
            logging.info("No more")
            self.stopped = True
        return retval


if __name__ == '__main__':
    bd = Interpreter(
        b'++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.>---.+++++++..+++.>>.<-.<.+++.------.--------.>>+.>++.')
    bd = Interpreter(b'++++>++++>++[<[.-].].')
    bd = Interpreter(b'+>------[<.>-]')
    print(bd.order)
    bd = Interpreter(b',.,.')
    # bd = Interpreter(b'+[--->++<]>+.................')
    bd.start()
    aa = bd.execute_until_end()
    print(len(aa))
    print(aa[0])
    print(aa)
    # print(bd.execute_until_return())
    # print(bd.execute_until_return())
    # print(bd.execute_until_return())
    # print(bd.execute_until_return())
    # print(bd.execute_until_return())
