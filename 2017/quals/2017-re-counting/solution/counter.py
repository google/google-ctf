import sys
import struct
import binascii

class Counter():
	TOTAL_LINES = 0x77
	CODE_FILEPOINTER = None

	def init(self):
		f = open("./code", "rb")
		self.CODE_FILEPOINTER = f.read()
		self.CODE_FILEPOINTER = self.CODE_FILEPOINTER[4:]
		
	def toDWord(self, code_buffer):
		return struct.unpack("<i", code_buffer)[0]
	def toQWord(self, code_buffer):
		return struct.unpack("<q", code_buffer)[0]
		
	def packQWord(self, value_buffer, offset, value):
		return struct.pack_into("<q", value_buffer, offset, value )

	def counter(self, key_buffer, code_line):
		di = key_buffer
		si = code_line
		dx = self.TOTAL_LINES
		bp = key_buffer
		while True:
			if si == self.TOTAL_LINES:
				return
			bx = si
			bx = bx << 4
			headerByte = self.toDWord(self.CODE_FILEPOINTER[bx:bx+4])
			if headerByte == 0:
				ax = self.CODE_FILEPOINTER[bx+4]
				si = self.toDWord(self.CODE_FILEPOINTER[bx+8:bx+8+4])
				_temp = self.toQWord(bp[ax*8:ax*8+8]) + 1
				self.packQWord(bp, ax*8, _temp)
			if headerByte == 1:
				ax = self.CODE_FILEPOINTER[bx+4]
				ax = ax * 8
				cx = self.toQWord(bp[ax:ax+8])
				#print("cx = " + str(cx))
				if cx != 0:
					cx = cx -1
					si = self.toDWord(self.CODE_FILEPOINTER[bx+8:bx+8+4])
					self.packQWord(bp, ax, cx)
				else:
					si = self.toDWord(self.CODE_FILEPOINTER[bx+12:bx+12+4])
			if headerByte == 2:
				di = 0xd0
				new_buffer = bytearray([0]*208)
				for i in range(208):
					new_buffer[i] = key_buffer[i]
				code_line = self.toDWord(self.CODE_FILEPOINTER[bx+8:bx+8+4])
				self.counter(new_buffer, code_line)
				ax = self.toDWord(self.CODE_FILEPOINTER[bx+4:bx+4+4])
				if ax != 0:
					ax = ax - 1
					dx = 0
					cx = ax*8+8
					bp[0:cx] = new_buffer[0:cx]
				si = self.toDWord(self.CODE_FILEPOINTER[bx+12:bx+12+4])
				dx = self.TOTAL_LINES
					
					
	

count = Counter()
count.init()

input_value = int(sys.argv[1])
key = bytearray(struct.pack("<q", input_value)) + bytearray([0]*200)
count.counter(key, 0)
result = str(hex(struct.unpack("<q", key[0:8])[0]))[2:]
if len(result) < 16:
	result = "0"*(16-len(result)) + result

print(binascii.hexlify(key))

print("---")
print("CTF{" + result + "}")


