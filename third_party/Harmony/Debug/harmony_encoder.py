import sys

def encode(s):
  result = ''
  for c in s:
    if not (32 < ord(c) < 127) or c in ('\\', '"'):
      result += '\\%03o' % ord(c)
    else:
      result += c
  return result
  
with open('0_harmony.cc', 'wb') as g:
      
    g.write("""#include "0_harmony.h"
    #include "stdafx.h"
    #include <string>

    #pragma unmanaged

    std::string zero_harmony() {
      std::string ret;
    """);

    with open('0harmony.dll', 'rb') as f:
      raw = f.read()

    n = 512
    chunks = [raw[i:i+n] for i in range(0, len(raw), n)]

    for chunk in chunks:
      g.write("  ret += std::string(\"")
      g.write(encode(chunk))
      g.write("\", ")
      g.write(str(len(chunk)))
      g.write(");\n")
     
    g.write("  return ret;\n}\n")
