# Copyright 2018 Google LLC
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

import struct
import zlib
from pprint import pprint

class Segment(object):
  def pprint(self):
    print(">"*8)
    if hasattr(self, 'offset'):
      print("! %s at %x"%(self.__class__.__name__, self.offset))
    else:
      print("! %s"%(self.__class__.__name__))
    pprint(zip(self.name, map(hex,self.fields)))
    if hasattr(self, 'print_local'):
      self.print_local()
    print("<"*8)

  def size(self):
    return len(self.dump())

  def hdr_size(self):
    return struct.calcsize(self.struc)

  def serialize_header(self):
    return struct.pack(self.struc, *self.fields)

class UnicodeComment(Segment):
  def __init__(self, data=""):
    self.name, self.fields, self.fmt = map(list,zip(*[
    ('signature', 0x6375, 'H'), # uc
    ('tsize', 0, 'H'),
    ('version', 1, 'B'),
    ('crc32', 0, 'I')
    ]))
    self.struc = "<" + "".join(self.fmt)
    self.comment = data

  def dump(self):
    self.fields[-3] = len(self.comment)
    self.fields[-1] = (zlib.crc32(self.comment))%(2**32)
    hdr = struct.pack(self.struc, *self.fields)
    return hdr + self.comment

class LFH(Segment):
  def __init__(self):
    self.sig = "PK\003\004"
    self.name, self.fields, self.fmt = zip(*[
    ('signature', 0x04034b50, 'I'), # 67324752
    ('version', 0, 'H'),
    ('gflag', 0, 'H'),
    ('compression', 0x0, 'H'),
    ('date', 0x0, 'I'),
    ('crc32', 0x0, 'I'),
    ('compressed-size', 0x0, 'I'),
    ('uncompressed-size', 0x0, 'I'),
    ('fname_len', 0x0, 'H'),
    ('xtra_field_len', 0x0, 'H')
    ])
    self.struc = "<" + "".join(self.fmt)
    self.fname = ""
    self.xtra = ""
    self.fdata = ""

  def matches(self, data):
    return data[:4] == self.sig

  def parse(self, data):
    hdr_size = struct.calcsize(self.struc)
    self.fields = list(struct.unpack(self.struc, data[:hdr_size]))
    name_end = hdr_size + self.fields[-2]
    xtra_end = name_end + self.fields[-1]
    file_end = xtra_end + self.fields[-4]
    self.fname = data[hdr_size:name_end]
    self.xtra = data[name_end:xtra_end]
    self.fdata = data[xtra_end:file_end]
    return file_end

  def print_local(self):
    print "name: " + self.fname

  def dump(self):
    self.fields[-2] = len(self.fname)
    self.fields[-1] = len(self.xtra)
    hdr = struct.pack(self.struc, *self.fields)
    return hdr + self.fname + self.xtra + self.fdata

  def injection_offset(self):
    hdr_size = struct.calcsize(self.struc)
    return self.offset + hdr_size + len(self.fname)

class CDH(Segment):
  def __init__(self):
    self.sig = "PK\x01\x02"
    self.name, self.fields, self.fmt = zip(*[
    ('signature', 0x02014b50, 'I'),
    ('version made by ', 0x0, 'H'),
    ('version to extract', 0x0, 'H'),
    ('gflag', 0x0, 'H'),
    ('compression', 0x0, 'H'),
    ('last_mod_time', 0x0, 'H'),
    ('last_mod_date', 0x0, 'H'),
    ('crc32', 0x0, 'I'),
    ('compressed-size', 0x0, 'I'),
    ('uncompressed-size', 0x0, 'I'),
    ('fname_len', 0x0, 'H'),
    ('xtra_field_len', 0x0, 'H'),
    ('file comment length', 0x0, 'H'),
    ('disk number start', 0x0, 'H'),
    ('internal file sttributes ', 0x0, 'H'),
    ('external file sttributes ', 0x0, 'I'),
    ('relative offset', 0x0, 'I')])
    self.file_name = ""
    self.file_comment = ""
    self.xtra = ""
    self.struc = "<" + "".join(self.fmt)

  def matches(self, data):
    return data[:4] == self.sig

  def print_local(self):
    print "name: " + self.file_name

  def parse(self, data):
    hdr_size = struct.calcsize(self.struc)
    self.fields = list(struct.unpack(self.struc, data[:hdr_size]))
    file_end = hdr_size + self.fields[-7]
    xtra_end = file_end + self.fields[-6]
    comment_end = xtra_end + self.fields[-5]
    self.file_name = data[hdr_size:file_end]
    self.xtra = data[file_end:xtra_end]
    self.file_comment = data[xtra_end:comment_end]
    return comment_end

  def dump(self):
    if getattr(self, 'update', True):
      self.fields[-7] = len(self.file_name)
      self.fields[-5] = len(self.file_comment)
      self.fields[-6] = len(self.xtra)
    hdr = struct.pack(self.struc, *self.fields)
    return hdr + self.file_name + self.file_comment + self.xtra

class ECDR(Segment):
  def __init__(self):
    self.sig = "PK\005\006"
    self.name, self.fields, self.fmt = zip(*[
    ('signature', 0x06054b50, 'I'),
    ('number of disk ', 0x0, 'H'),
    ('number of disk w central', 0x0, 'H'),
    ('total number of entries in disk', 0x0, 'H'),
    ('total number of entries in cd', 0x0, 'H'),
    ('sz of cd', 0x0, 'I'),
    ('weird offset ', 0x0, 'I'),
    ('comment_size', 0x0, 'H')
    ])
    self.zip_comment = ""
    self.struc = "<" + "".join(self.fmt)

  def matches(self, data):
    return data[:4] == self.sig

  def parse(self, data):
    hdr_size = struct.calcsize(self.struc)
    self.fields = list(struct.unpack(self.struc, data[:hdr_size]))
    end = hdr_size + self.fields[-1]
    self.zip_comment = data[hdr_size:end]
    return end

  def dump(self):
    self.fields[-1] = len(self.zip_comment)
    hdr = struct.pack(self.struc, *self.fields)
    return hdr + self.zip_comment

# Barrier class, will throw if there is additional information in the zip.
class BYTE(object):
  def __init__(self):
    self.byte = ""
  def matches(self, data):
    return True

  def parse(self, data):
    raise Exception
    self.byte = data[0]
    return 1

  def dump(self):
    return self.byte

def parse_zip(data):
  segments = []
  offset = 0
  while offset < len(data):
    candidates = (LFH(), CDH(), ECDR(), BYTE())
    for c in candidates:
      if c.matches(data[offset:]):
        c.offset = offset
        offset += c.parse(data[offset:])
        segments.append((c, data[c.offset:offset]))
        break
  # Ensure you can regenerate the zips.
  for (x,d) in segments:
      assert x.dump() == d
  return [x for (x, _) in segments]

COMMENT_HEADER_SIZE = UnicodeComment().hdr_size()

def parse_from_back(data):
  e = ECDR()
  for i in range(len(data), 0, -1):
    if e.matches(data[i:]):
      e.parse(data[i:])
      e.pprint()
      break
  cdhs = []
  i = e.fields[-2]
  for _ in range(3):
    c = CDH()
    i += c.parse(data[i:])
    cdhs.append(c)
    c.pprint()

def merge(f1, f2):
  "Merges the contents of f1 and f2, repeating the first file of f1 on f2."
  f1_lfhs =  [x for x in f1 if isinstance(x, LFH)]
  f1_cdhs =  [x for x in f1 if isinstance(x, CDH)]
  f1_ecdr, = [x for x in f1 if isinstance(x, ECDR)]
  f2_lfhs =  [x for x in f2 if isinstance(x, LFH)]
  f2_cdhs =  [x for x in f2 if isinstance(x, CDH)]
  f2_ecdr, = [x for x in f2 if isinstance(x, ECDR)]

  lhr_pointer = 0
  right_lfh_offsets = [
      # block present in both.
      0,
      # first real block.
      f1_lfhs[0].hdr_size() + len(f1_lfhs[0].fname) + COMMENT_HEADER_SIZE
  ]

  # Pack the first pieces of the right LFH into the first LFH comment.
  fake_comment_size = (len(f1_lfhs[0].fdata) +
                       f1_lfhs[1].hdr_size() +
                       len(f1_lfhs[1].fname) +
                       COMMENT_HEADER_SIZE)
  f2_lfhs[0].fields[-1] = fake_comment_size + COMMENT_HEADER_SIZE
  f1_lfhs[0].xtra = UnicodeComment(
      # The contents of LHR, fname and
      f2_lfhs[0].serialize_header() +
      f2_lfhs[0].fname +
      # a fake comment header to wrap the next section.
      UnicodeComment('a'*(fake_comment_size)).serialize_header()).dump()

  fake_comment_size = (len(f1_lfhs[1].fdata) +
                       f1_lfhs[2].hdr_size() +
                       len(f1_lfhs[2].fname) +
                       COMMENT_HEADER_SIZE)
  f2_lfhs[1].fields[-1] = fake_comment_size + COMMENT_HEADER_SIZE
  # Fix the second LHR comment.
  f1_lfhs[1].xtra = UnicodeComment(
      # The contents of LHR, fname and
      f2_lfhs[0].fdata +
      f2_lfhs[1].serialize_header() +
      f2_lfhs[1].fname +
      # a fake comment header to wrap the next section.
      UnicodeComment('a'*fake_comment_size).serialize_header()).dump()

  right_lfh_offsets.append(
      f1_lfhs[0].size() +
      f1_lfhs[1].hdr_size() +
      len(f1_lfhs[1].fname) +
      COMMENT_HEADER_SIZE +
      len(f2_lfhs[0].fdata))

  # fix the cdh pointers
  f1_cdhs[1].fields[-1] = f1_lfhs[0].size()
  f1_cdhs[2].fields[-1] = f1_lfhs[0].size() + f1_lfhs[1].size()

  # Append the new file header.
  t = LFH()
  t.parse(f1_cdhs[0].dump())
  f2_cdhs = [t] + f2_cdhs
  f2_cdhs[0].fields[-1], f2_cdhs[1].fields[-1], f2_cdhs[2].fields[-1] = (
      right_lfh_offsets)
  # Add fake comment offset to cover the f1 sections
  f2_cdhs[2].dump()  #update values
  f2_cdhs[2].fields[-5] = (
      len(f1_lfhs[2].fdata) +
      f1_cdhs[0].size() +
      f1_cdhs[1].size() +
      f1_cdhs[2].size() +
      f1_ecdr.hdr_size()
  )
  f2_cdhs[2].update = False
  f2_cdhs[0].fields[7] = 0

  # Fix the second LHR comment.
  f1_lfhs[2].xtra = UnicodeComment(
      # The contents of LHR, fname and
      f2_lfhs[1].fdata +
      f2_cdhs[1].dump() +
      f2_cdhs[0].dump() +
      f2_cdhs[2].dump()
  ).dump()

  # Fix the left ecdr offset.
  f1_ecdr.fields[-2] = sum(x.size() for x in f1_lfhs)
  # Fix the right ecdr offset
  f2_ecdr.fields[-2] = (
      f1_lfhs[0].size() +
      f1_lfhs[1].size() +
      f1_lfhs[2].hdr_size() +
      len(f1_lfhs[2].fname) +
      len(f1_lfhs[1].fdata) +
      COMMENT_HEADER_SIZE
      )
  # Update the size to reflect that the right zip has 3 objects now.
  f2_ecdr.fields[-4] += 1
  f2_ecdr.fields[-5] += 1
  # size of central directory
  f2_ecdr.fields[-3] = sum(x.size() for x in f2_cdhs) + f2_cdhs[2].fields[-5]

  # Insert a wrong disk count to make 7zip skip this file.
  f2_ecdr.fields[2] = 1
  # Pack the right ecdr into the left ecdr
  f1_ecdr.zip_comment = f2_ecdr.dump()

  return "".join(x.dump() for x in f1_lfhs + f1_cdhs + [f1_ecdr])

if __name__ == "__main__":
  import sys
  f1 = parse_zip(open(sys.argv[1]).read())
  f2 = parse_zip(open(sys.argv[2]).read())
  print "#"*8 + " F1 " + "#"*8
  [x.pprint() for x in f1]
  print "#"*8 + " F2 " + "#"*8
  [x.pprint() for x in f2]
  print "#"*8 + " MERGED " + "#"*8
  m = merge(f1,f2)
  # Parsed from the front.
  [x.pprint() for x in parse_zip(m)]
  # Parsed from the back.
  parse_from_back(m)
  open('reordered.zip', 'w').write(m)

