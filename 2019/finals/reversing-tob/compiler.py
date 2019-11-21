#!/usr/bin/env python2
# -------------------------------------------------------------------------------------------------
# Copyright 2019 Google LLC
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
# -------------------------------------------------------------------------------------------------
#
# Google CTF 2019 Finals - The Onion Binary (RE)
#
# * * * VM Compiler * * *
#
# This program takes a *.tob program as input and generates a custom VM bytecode. Each instruction
# consists of 5 32-bit fields:
#
#       +------------+--------+------------+----------------------+----------------------+
#       | Nest Level | Opcode | Operand #1 | Operand #2 or Random | Operand #3 or Random |
#       +------------+--------+------------+----------------------+----------------------+
#
#       Nest Level: The indentation of current instruction (how deep is inside brackets)
#       Opcode    : Instruction opcode
#       Operand #1: The first operand of the instruction
#       Operand #2: The second operand of the instruction, or a a random value if not exists
#       Operand #3: The third operand of the instruction, or a a random value if not exists
#
# NOTE: One special exception is with print statements, where Operand #1 can be arbitrarily long.
#       In that case, string is NULL terminated, so we can easily find where the next instruction
#       starts.
#
# Since we don't have goto instructions nor we use relative offsets, the nest level approach is a
# neat trick to quickly infer in which block each instruction belongs.
#
# Registers: VM supports 26 registers [a-z]
#
# Instruction Opcodes:
#       mem_read : 0x932
#       mem_write: 0x933
#       mov      : 0x85
#       add      : 0x88
#       sub      : 0x136
#       mul      : 0x22
#       div      : 0x93
#       mod      : 0x1000
#       xor      : 0x10001
#       print    : 0x42 and 0x43
#       read     : 0x44
#       if       : 0x4004
#       while    : 0x11
#       break    : 0x7
#       continue : 0x1
#       nop      : 0xcc
#       halt     : 0xdead
#
# Running Example: ./compiler.py -o crackme.bin
# --------------------------------------------------------------------------------------------------
import struct
import sys
import argparse
import datetime
import textwrap
import shlex
import re
import random


nest_level = 0x64
stack = [nest_level]

OPERATORS = {
    '<'  : 0x1434,
    '>'  : 0x1435,
    '<=' : 0x1436,
    '>=' : 0x1437,
    '==' : 0x1438,
    '!=' : 0x1439
}


# --------------------------------------------------------------------------------------------------
# Some lambdas to convert a token to a register and to an integer, just to make code readability
# easier.
#
mk_int  = lambda token: int(token, 0)
mk_reg = lambda token: ord(token) - 0x61


# --------------------------------------------------------------------------------------------------
# Performs a regular regex matching on a 2 lists (matches element by element).
#
def re_list_match(*args):
    regexes, tokens = args[:-1], args[-1]           # last argument is the token list

    if len(regexes) != len(tokens):                 # do the base check
        return False

    for regex, token in zip(regexes, tokens):
        if re.search(regex, token) is None:         # if we have a mismatch
            return False                            # lists do not match

    return True                                     # everything is equal. Success!


# --------------------------------------------------------------------------------------------------
# Given all instruction operands, builds its bytecode.
#
def make_instruction(*operands):
    bytecode = struct.pack("<L", stack[-1])         # nest level first
    pretty_print = '| 0x%x ' % stack[-1]            # pretty-print instruction

    for operand in operands:                        # pack each operand
        if isinstance(operand, int):
            bytecode += struct.pack("<L", operand)
            pretty_print += '| 0x%x ' % operand

        elif isinstance(operand, str):
            bytecode += operand
            pretty_print += '| %s ' % operand
        else:
            raise Exception("Unknown operand type '%s'" % type(operand))

    pretty_print += '|'

    return bytecode, pretty_print


# --------------------------------------------------------------------------------------------------
# Memory I/O: Compile memory ready. Example: 'a = *b' =>  * | 0x932 | 0x00 | 0x01 |
#
def compile_mem_read(tokens):
    return make_instruction(0x932, mk_reg(tokens[0]), mk_reg(tokens[2][1:]))


# --------------------------------------------------------------------------------------------------
# Arithmetic: Compile mov. Example: '*b = c' =>  * | 0x933 | 0x01 | 0x02 |
#
def compile_mem_write(tokens):
     return make_instruction(0x933, mk_reg(tokens[0][1:]), mk_reg(tokens[2]))


# --------------------------------------------------------------------------------------------------
# Arithmetic: Compile mov. Example: 'b = 33' =>  * | 0x85 | 0x01 | 0x21 |
#
def compile_mov(tokens):
    match = re.search(r'^([a-z])$', tokens[2])
    if match is not None:
        # Case #1: r-value is a register
        return make_instruction(0x85, mk_reg(tokens[0]), 0xcff, mk_reg(match.group(1)))
    else:
        # Case #2: r-value is a constant
        return make_instruction(0x85, mk_reg(tokens[0]), 0xde1, mk_int(tokens[2]))


# --------------------------------------------------------------------------------------------------
# Arithmetic: Compile add. Example: 'd += 2' =>  * | 0x88 | 0x03 | 0x2 |
#
def compile_add(tokens):
    match = re.search(r'^([a-z])$', tokens[2])
    if match is not None:
        # Case #1: r-value is a register
        return make_instruction(0x88, mk_reg(tokens[0]), 0xcfe, mk_reg(match.group(1)))
    else:
        # Case #2: r-value is a constant
        return make_instruction(0x88, mk_reg(tokens[0]), 0xde2, mk_int(tokens[2]))


# --------------------------------------------------------------------------------------------------
# Arithmetic: Compile sub.
#
def compile_sub(tokens):
    match = re.search(r'^([a-z])$', tokens[2])
    if match is not None:
        # Case #1: r-value is a register
        return make_instruction(0x136, mk_reg(tokens[0]), 0xcfd, mk_reg(match.group(1)))
    else:
        # Case #2: r-value is a constant
        return make_instruction(0x136, mk_reg(tokens[0]), 0xde3, mk_int(tokens[2]))


# --------------------------------------------------------------------------------------------------
# Arithmetic: Compile mul.
#
def compile_mul(tokens):
    match = re.search(r'^([a-z])$', tokens[2])
    if match is not None:
        # Case #1: r-value is a register
        return make_instruction(0x22, mk_reg(tokens[0]), 0xcfb, mk_reg(match.group(1)))
    else:
        # Case #2: r-value is a constant
        return make_instruction(0x22, mk_reg(tokens[0]), 0xde4, mk_int(tokens[2]))


# --------------------------------------------------------------------------------------------------
# Arithmetic: Compile div.
#
def compile_div(tokens):
    match = re.search(r'^([a-z])$', tokens[2])
    if match is not None:
        # Case #1: r-value is a register
        return make_instruction(0x93, mk_reg(tokens[0]), 0xcfa, mk_reg(match.group(1)))
    else:
       # Case #2: r-value is a constant
        return make_instruction(0x93, mk_reg(tokens[0]), 0xde5, mk_int(tokens[2]))


# --------------------------------------------------------------------------------------------------
# Arithmetic: Compile modulo. Example: 'e %= 16' =>  * | 0x1000 | 0x05 | 0x10 |
#
def compile_mod(tokens):
    match = re.search(r'^([a-z])$', tokens[2])
    if match is not None:
        # Case #1: r-value is a register
        return make_instruction(0x1000, mk_reg(tokens[0]), 0xcf9, mk_reg(match.group(1)))
    else:
       # Case #2: r-value is a constant
        return make_instruction(0x1000, mk_reg(tokens[0]), 0xde6, mk_int(tokens[2]))


# --------------------------------------------------------------------------------------------------
# Arithmetic: Compile xor. Example: 'a ^= 5' =>  * | 0x10001 | 0x00 | 0x5 |
#
def compile_xor(tokens):
    match = re.search(r'^([a-z])$', tokens[2])
    if match is not None:
        # Case #1: r-value is a register
        return make_instruction(0x10001, mk_reg(tokens[0]), 0xcf8, mk_reg(match.group(1)))
    else:
        # Case #2: r-value is a constant
        return make_instruction(0x10001, mk_reg(tokens[0]), 0xde7, mk_int(tokens[2]))


# --------------------------------------------------------------------------------------------------
# I/O: Compile print. Examples: 1) 'print a' 2) 'print "this is some foo text"'
#
def compile_print(tokens):
    # Case #1: Print the output of a register
    match = re.search(r'^([a-z])$', tokens[1])
    if match is not None:
        return make_instruction(0x42, mk_reg(match.group(1)))

    # Case #2: Print a constant string
    match = re.search(r'^\"(.*)\"$', tokens[1])
    if match is not None:
        # Simple encoding on the string to avoid "strings" grep
        str_encode = lambda cstr: ''.join(chr(ord(s) ^ 0xa7) for s in cstr)

        return make_instruction(0x43, str_encode(match.group(1)) + '\x00')


# --------------------------------------------------------------------------------------------------
# I/O: Compile read (i.e., scanf). Example: 'read d' reads a 32 bit number from stdin and stores it
#   in register 'd'.
#
def compile_read(tokens):
    match = re.search(r'^([a-z])$', tokens[1])
    if match is not None:
        return make_instruction(0x44, mk_reg(match.group(1)))


# --------------------------------------------------------------------------------------------------
# Conditional: Compile if. Example: 'if (a > 30) { ....'  => * | 0x4004 | 0x00 | 0x1435 | 0x1e |
#
def compile_if(tokens):
    global stack, nest_level

    nest_level += 1 + random.randint(0, 0)          # update nest level
    stack.append(nest_level)                        # move on the next nest level

    return make_instruction(0x4004, mk_reg(tokens[2]), OPERATORS[tokens[3]], mk_int(tokens[4]))


# --------------------------------------------------------------------------------------------------
# Conditional: Compile while. Example: 'while (b < 10) { ....'
#   => * | 0x4004 | 0x01 | 0x1434 | 0xa |
#
def compile_while(tokens):
    global stack, nest_level

    nest_level += 1 + random.randint(0, 0)          # update nest level
    stack.append(nest_level)                        # move on the next nest level

    return make_instruction(0x11, mk_reg(tokens[2]), OPERATORS[tokens[3]], mk_int(tokens[4]))


# --------------------------------------------------------------------------------------------------
# Conditional: End bracket statement. This is not an actual statement as no bytecode is generated
# for this statement. This is just updates nest level.
#
def compile_bracket_end(tokens):
    global stack, nest_level

    try:
        stack.pop()
        nest_level = stack[-1]

        return make_instruction(0xcc)
    except IndexError:
        print '[!] Error. Nest stack empty. More close brackets that open ones?'
        exit(0)


# --------------------------------------------------------------------------------------------------
# Special: Compile break.
#
def compile_break(tokens):
    return make_instruction(0x7)


# --------------------------------------------------------------------------------------------------
# Special: Compile break.
#
def compile_continue(tokens):
    return make_instruction(0x1)


# --------------------------------------------------------------------------------------------------
# Special: No-operation. Used as a delimiter after if/while. This is used to distinguish between
# consecutive if or while statements where the nest level increases. The nop drops down nest level
# right after if/while.
#
def compile_nop(tokens):
    return make_instruction(0xcc)


# --------------------------------------------------------------------------------------------------
# Special: Halt VM execution.
#
def compile_halt(tokens):
    return make_instruction(0xdead)


# --------------------------------------------------------------------------------------------------
# Does a syntax analysis on the VM source code and compiles it statement by statement.
#
def syntax_parsing(tokens):
    if re_list_match(r'^[a-z]$', r'^=$', r'^\*[a-z]$', tokens):
        vm_code, pretty_print = compile_mem_read(tokens)

    elif re_list_match(r'^\*[a-z]$', r'^=$', r'^[a-z]$', tokens):
        vm_code, pretty_print = compile_mem_write(tokens)

    elif re_list_match(r'^[a-z]$', r'^=$', r'^[0-9]+|0x[0-9a-fA-F]+|[a-z]$', tokens):
        vm_code, pretty_print = compile_mov(tokens)

    elif re_list_match(r'^[a-z]$', r'^\+=$', r'^[0-9]+|0x[0-9a-fA-F]+|[a-z]$', tokens):
        vm_code, pretty_print = compile_add(tokens)

    elif re_list_match(r'^[a-z]$', r'^-=$', r'^[0-9]+|0x[0-9a-fA-F]+|[a-z]$', tokens):
        vm_code, pretty_print = compile_sub(tokens)

    elif re_list_match(r'^[a-z]$', r'^\*=$', r'^[0-9]+|0x[0-9a-fA-F]+|[a-z]$', tokens):
        vm_code, pretty_print = compile_mul(tokens)

    elif re_list_match(r'^[a-z]$', r'^/=$', r'^[0-9]+|0x[0-9a-fA-F]+|[a-z]$', tokens):
        vm_code, pretty_print = compile_div(tokens)

    elif re_list_match(r'^[a-z]$', r'^%=$', r'^[0-9]+|0x[0-9a-fA-F]+|[a-z]$', tokens):
        vm_code, pretty_print = compile_mod(tokens)

    elif re_list_match(r'^[a-z]$', r'^\^=$', r'^[0-9]+|0x[0-9a-fA-F]+|[a-z]$', tokens):
        vm_code, pretty_print = compile_xor(tokens)

    elif re_list_match(r'^print', r'^[a-z]|\".*\"$', tokens):
        vm_code, pretty_print = compile_print(tokens)

    elif re_list_match(r'^read', r'^[a-z]|\".*\"$', tokens):
        vm_code, pretty_print = compile_read(tokens)

    elif re_list_match(r'^if$', r'^\($', r'^[a-z]$', r'^<|>|==|!=$', r'^\s*[0-9]+|0x[0-9a-fA-F]+$',
                       r'^\)$', r'^\s*{', tokens):
        vm_code, pretty_print = compile_if(tokens)

    elif re_list_match(r'^while$', r'^\($', r'^[a-z]$', r'^<|>|==|!=$',
                       r'^\s*[0-9]+|0x[0-9a-fA-F]+$', r'^\)$', r'^\s*{', tokens):
        vm_code, pretty_print = compile_while(tokens)

    elif re_list_match(r'^}$', tokens):
        vm_code, pretty_print = compile_bracket_end(tokens)

    elif re_list_match(r'^break$', tokens):
        vm_code, pretty_print = compile_break(tokens)

    elif re_list_match(r'^continue$', tokens):
        vm_code, pretty_print = compile_continue(tokens)

    elif re_list_match(r'^halt$', tokens):
        vm_code, pretty_print = compile_halt(tokens)

    else:
        print '[!] Error. Cannot parse tokens:', tokens
        exit(0)

    return vm_code, pretty_print


# --------------------------------------------------------------------------------------------------
# Does a lexical analysis on the VM source code.
#
def lexical_analysis(filename):
    lineno = 0

    with open(filename, "r") as file:               # open source file
        for line in file:                           # and process it line by line
            # drop all comments ";" from current line (be careful though to not
            # drop "comments" that are inside quotes)
            # line = re.sub("(?!\B\"[^\"]*);(?![^\"]*\"\B).*\n", '', line)

            # tokenize line and append it to the token list
            lexical = shlex.shlex(line)             # create a lexical analysis object
            ops = '+-*/%' + '&|~^' + '<>!='         # set word chars
            lexical.commenters = ';'                # set semicolon as comment
            lexical.wordchars += ops

            tokens = [token for token in lexical]
            if tokens:                              # if there are any tokens
                yield lineno, tokens

            lineno = lineno + 1                     # update line counter


# -------------------------------------------------------------------------------------------------
# Parses command line arguments.
#
def parse_args():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)

    # positional argument
    parser.add_argument(
        help     = 'Source code of the emulated program (*.tob)',
        action   = 'store',
        dest     = 'source',
    )

    parser.add_argument(
        '-o', '--output',
        help     = 'Output file to hold the compiled bytecode',
        action   = 'store',
        dest     = 'output',
        default  = 'a.out'
    )

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    return parser.parse_args()                      # do the parsing (+ error handling)


# --------------------------------------------------------------------------------------------------
# Main compiler routine.
#
if __name__ == "__main__":
    args = parse_args()                             # process arguments
    now = datetime.datetime.now()                   # get current time

    print textwrap.dedent('''
        %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
        %                                                                    %
        %            :::::::::::       ::::::::        :::::::::             %
        %               :+:          :+:    :+:       :+:    :+:             %
        %              +:+          +:+    +:+       +:+    +:+              %
        %             +#+          +#+    +:+       +#++:++#+                %
        %            +#+          +#+    +#+       +#+    +#+                %
        %           #+#          #+#    #+#       #+#    #+#                 %
        %          ###           ########        #########                   %
        %                                                                    %
        %                     The Onion Binary Compiler                      %
        %                                                                    %
        %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
        ''')
    print "[*] Starting TOB compiler at %s" % now.strftime("%d/%m/%Y %H:%M")


    vm_bytecode = ''
    for lineno, tokens in lexical_analysis(args.source):
        print '[+] Parsing line %d ... Tokens:' % (lineno), tokens

        insn_bytecode, pretty_print = syntax_parsing(tokens)
        print "[+]\tInstruction bytecode: '%s'" % pretty_print

        vm_bytecode += insn_bytecode

    # add the program termination instruction
    insn_bytecode, pretty_print = make_instruction(0xffff)
    vm_bytecode += insn_bytecode

    # check for bracket mismatch.
    if len(stack) != 1:
        print '[!] Error. Nest stack is not empty. Forgot to close a bracket?'
        exit(0)

    # write bytecode to a file
    with open(args.output, "w") as fp:
        fp.write(vm_bytecode)

    # print bytecode to stdout
    print 'Compiled VM program (copy paste it on the decoder):'

    line = '\t'
    ctr = 1
    for byte in vm_bytecode:
        line += '0x%02x, ' % ord(byte)

        if ctr % 16 == 0:
            line += '\n\t'

        ctr += 1

    # clear any leftovers
    if line.endswith('\n\t'):
        line = line[:-2]

    if line.endswith(', '):
        line = line[:-2]

    print '%s' % line
    print 'VM size: %d' % ctr

# --------------------------------------------------------------------------------------------------
