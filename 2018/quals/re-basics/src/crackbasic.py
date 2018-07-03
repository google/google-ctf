#!/usr/bin/python
# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#
# CrackBASIC - A nasty hack of a C64 BASIC compiler by Gynvael Coldwind. Sorry.
#
# No, seriously, don't use it for anything serious (why would you code anything
# serious in C64 BASIC nowadays anyway?). The code is quite horrible as this is
# a one-time-hack anyway.
#
# Some notes:
# - This does .upper() on the whole source file. Yes, it's that kind of a hack.
# - Added hexadecimal literals (how could C64 basic not have them?!), e.g. &12ab
# - You can use # comments, but only if # is the first character in the line.
# - Empty lines are ignored.
# - Sometimes you need to add a whitespace here and there for things to compile
#   correctly. I didn't want to spend too much time on this and that's one of
#   the artifacts - sorry!
# - You can use {rawaddr LINE_NO OFFSET W/L/H [LABEL]} to get in-runtime-memory
#   address of the specified BASIC line. OFFSET can be negative too. LABEL is
#   optional; if not specified it defaults to "__DEFAULT".
# - You can specify a separate "namespace" for the basic code using .label. The
#   default label is "__DEFAULT". The label can then be used with {rawaddr ...}
#   to uniquely identify a line (note: yes, you can have multiple lines with the
#   same number; it's a linked list in the end, the line numbers matter only for
#   GOTO/GOSUB instructions).
# - You can use .slash_list to make sure next line has a NULL-ptr in the "next"
#   field of the linked list (i.e. same as the last node would have).
# - You can use .encrypted_start 0xKEY and .encrypted_end to obfuscate parts
#   of the linked list. You have to fix it at runtime though.
#     # Decryption routine in CrackBASIC:
#     70 for i = es to ee
#     71 k = ( peek(i) + ek ) and 255
#     72 print i , peek(i) , k : poke i, k
#     73 next i
#     74 return
# - You can use .include to include other BAS files. This breaks error reporting
#   however. Oh well.
# - Even with all the flaws and bugs this still can be used to create a decent
#   CrackMe / ReverseMe / OptimizeMe (or so I tell myself).

import sys
import time
import os
import string
import copy

from tokens import *
from byteops import *

STATE_NORMAL = 0
STATE_QUOTED = 1

BASIC_DIRECTIVES = {
  "TEST": "basic_directive_test",
  "RAWADDR": "basic_directive_rawaddr",
}

def basic_directive_test(ctx, d, args):
  return [4, "1234"]

def basic_directive_rawaddr(ctx, d, args):
  args = args.split(" ")
  line_no = int(args[0])
  offset = int(args[1])
  selector = args[2]
  label = "__DEFAULT"

  if len(args) == 4:
    label = args[3]

  if selector not in {"L", "H", "W"}:  # Low-byte, High-byte, full-Word
    sys.exit("Syntax error: rawaddr has invalid selector on line %i" % (
        ctx["file_line_number"]))

  return [5, ["RAWADDR", (line_no, offset, selector, label)]]

def basic_handle_directive(ctx, token):
  tokens = token.split(" ", 1)
  directive = tokens[0]

  if len(tokens) == 1:
    args = None
  else:
    args = tokens[1]

  if directive not in BASIC_DIRECTIVES:
    sys.exit("Syntax error: unknown directive on line %i (BASIC line %i)" % (
        ctx["file_line_number"], ctx["line_no"]))

  handler = globals()[BASIC_DIRECTIVES[directive]]

  return handler(ctx, directive, args)

def basic_handle_special(ctx, ln):
  if ln.strip() == ".SLASH_LIST":
    return {
        "type": "SLASH_LIST"
    }

  if ln.strip().startswith(".LABEL "):
    label = ln.strip().split(' ')[1]
    return {
        "type": "LABEL",
        "label": label
    }

  if ln.strip().startswith(".INCLUDE "):
    fname = ln.strip().split(' ')[1]
    return {
        "type": "INCLUDE",
        "fname": fname
    }

  if ln.strip().startswith(".ENCRYPTED_START "):
    key = int(ln.strip().split(' ')[1], 16)
    return {
        "type": "ENCRYPTED_START",
        "key": key
    }

  if ln.strip() == ".ENCRYPTED_END":
    return {
        "type": "ENCRYPTED_END"
    }

  sys.exit("Syntax error: unknown special on line %i" % (
      ctx["file_line_number"]))

def basic_compile_line(ctx, ln):
  if not ln.strip():
    return {
        "type": "EMPTY"
    }

  if ln.startswith("#"):
    return {
        "type": "COMMENT"
    }

  if ln.startswith("."):
    return basic_handle_special(ctx, ln)

  i = 0

  # Grab the line number first.
  line_no = ""
  while i < len(ln):
    if ln[i] not in string.digits:
      break
    line_no += ln[i]
    i += 1

  line_no = int(line_no)
  ctx["line_no"] = line_no

  # If there is a space, skip it.
  if ln[i] == " ":
    i += 1

  # Dict-compress the code.
  out = []
  ctx["token"] = ""

  def commit_token():
    if ctx["token"]:
      out.append([len(ctx["token"]), ctx["token"]])
      ctx["token"] = ""

  while i < len(ln):

    # Handle quoted strings first.
    if ln[i] == "\"":
      commit_token()
      ctx["token"] = "\""

      i += 1
      while i < len(ln) and ln[i] != "\"":
        ctx["token"] += ln[i]
        i += 1

      if ln[i] != "\"":
        sys.exit("Syntax error: missing \" on line %i (BASIC line %i)" % (
            ctx["file_line_number"], line_no))
      ctx["token"] += "\""
      i += 1
      commit_token()
      continue

    # Handle space and :.
    if ln[i] in {" ", ":"}:
      commit_token()
      out.append([1, ln[i]])
      i += 1
      continue

    # Handle ?.
    if ln[i] == "?":
      commit_token()
      out.append([1, db(BASIC_TOKENS["PRINT"])])
      i += 1
      continue

    # Handle &1234 (hex literal) extension.
    if ln[i] == "&":
      commit_token()
      i += 1
      j = 0
      while i+j < len(ln) and j < 4 and ln[i+j] in "0123456789ABCDEF":
        ctx["token"] += ln[i+j]
        j += 1
      if j == 0:
        sys.exit("Syntax error: invalid hex literal & on line %i (BASIC line %i)" % (
            ctx["file_line_number"], line_no))
      s = str(int(ctx["token"], 16))
      out.append([len(s), s])
      ctx["token"] = ""
      i += j
      continue

    # Handle {directive} extension.
    if ln[i] == "{":
      commit_token()

      i += 1  # Skip the {.

      while i < len(ln) and ln[i] != "}":
        ctx["token"] += ln[i]
        i += 1

      if ln[i] != "}":
        sys.exit("Syntax error: missing } on line %i (BASIC line %i)" % (
            ctx["file_line_number"], line_no))
      i += 1

      out.append(basic_handle_directive(ctx, ctx["token"]))
      ctx["token"] = ""

      continue

    # Handle any other character.
    ctx["token"] += ln[i]
    if ctx["token"] in BASIC_TOKENS:
      out.append([1, db(BASIC_TOKENS[ctx["token"]])])
      ctx["token"] = ""
      i += 1
      continue

    i += 1

  commit_token()

  len_tokens = sum([token[0] for token in out])
  next_line = ctx["addr"] + len_tokens + 5

  s = {
      "addr": ctx["addr"],
      "type": "LINE",
      "next_line": next_line,
      "line_no": line_no,
      "tokens": out,
  }

  #print "BASIC Line %i --> Addr %i (0x%x)" % (s["line_no"], s["addr"], s["addr"])

  ctx["addr"] = next_line

  return s

def basic_post_rawaddr(data, line_no, offset, selector, label):
  currlabel = "__DEFAULT"

  addr = None
  for s in data:
    if s["type"] == "LABEL":
      currlabel = s["label"]
      continue

    if s["type"] != "LINE":
      continue

    if currlabel != label:
      continue

    if s["line_no"] == line_no:
      addr = s["addr"]
      break

  if addr is None:
    sys.exit("Rawaddr error: could not find BASIC line %i" % line_no)

  v = addr + offset
  if selector == "H":
    v = (v >> 8) & 0xff
  elif selector == "L":
    v = v & 0xff
  else:
    pass  # Keep the 16-bit word.

  ret = str(v).rjust(5, "0")

  return ret

def basic_postprocess(data):

  final_data = []

  slash_next = False
  for s in data:
    if s["type"] in {"EMPTY", "COMMENT", "LABEL"}:  # SKIP
      continue

    if s["type"] == "SLASH_LIST":
      slash_next = True
      continue

    if s["type"] in {"ENCRYPTED_START", "ENCRYPTED_END"}:
      final_data.append(s)  # Pass to next step.
      continue


    if s["type"] == "LINE":

      for i, v in enumerate(s["tokens"]):
        token_len, token = v

        if type(token) is str:
          continue

        # Postprocessing starts here.
        post_type, post_args = token

        if post_type == "RAWADDR":
          ret = basic_post_rawaddr(data, *post_args)
        else:
          sys.exit("Unknown token (x): %s" % (`s`))

        # In-place replace.
        s["tokens"][i][0] = len(ret)
        s["tokens"][i][1] = ret


      if slash_next:
        slash_next = False
        s = copy.deepcopy(s)  # Make sure that data still holds the correct values.

        s["next_line"] = 0
        s["line_no"] = 0

      final_data.append(s)
      continue

    sys.exit("Unknown entry (1): %s" % (`s`))


  # Connect tokens to string.
  final = [
      dw(0x0801)  # Address to load to.
  ]

  enc_key = None
  def perhaps_encrypt(s):
    if enc_key is None:
      return s
    return ''.join([
        chr((ord(ch) - enc_key) & 0xff) for ch in s
    ])

  for s in final_data:

    if s["type"] == "ENCRYPTED_START":
      enc_key = s["key"]
      continue

    if s["type"] == "ENCRYPTED_END":
      enc_key = None
      continue

    if s["type"] == "LINE":
      final.append(perhaps_encrypt(dw(s["next_line"])))
      final.append(perhaps_encrypt(dw(s["line_no"])))

      for token_len, token in s["tokens"]:
        if type(token) is str:
          final.append(perhaps_encrypt(token))
          continue

        sys.exit("Postprocessing error: unhandled token type %s in BASIC line %i" % (
            `token`, s["line_no"]))

      final.append(perhaps_encrypt(db(0)))
      continue

    sys.exit("Unknown entry (2): %s" % (`s`))

  # Finalize.
  final.append(dw(0x0000))  # End of linked list.

  return ''.join(final)


def basic_compile(lines):
  ctx = {
      "addr": 0x0801,  # Current line address.
      "file_line_number": None,
      "line_no": None
  }
  data = []

  for i, ln in enumerate(lines):
    ctx["file_line_number"] = i + 1
    ctx["line_no"] = None

    ret = basic_compile_line(ctx, ln)
    if ret["type"] == "INCLUDE":
      # Insert file's content here.
      # Oh btw, this feature totally breaks file_line_number. Oh well.
      with open(ret["fname"], "r") as f:
        included_lines = f.read().upper().splitlines()
        # So extending a currently enumerated list is a little tricky, but
        # CPython 2.7.14 which I'm using seems to be handling this OK.
        lines[(i+1):(i+1)] = included_lines

    else:
      data.append(ret)

  # Done.
  return data

def main():
  if len(sys.argv) != 2:
    sys.exit("usage: crackbasic.py <file.bas>")

  name_in = sys.argv[1]
  name_out = os.path.splitext(name_in)[0] + ".prg"

  print "Reading...",
  with open(name_in, "r") as f:
    lines = f.read().upper().splitlines()
  print "%i lines" % len(lines)

  print "First pass...",
  data = basic_compile(lines)
  print "%i lines" % len(data)

  print "Second pass...",
  data = basic_postprocess(data)
  print "%i bytes" % len(data)

  print "Writing...",
  with open(name_out, "wb") as f:
    f.write(data)
  print "Done!"

if __name__ == "__main__":
  main()

