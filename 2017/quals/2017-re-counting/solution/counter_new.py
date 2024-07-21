import sys
import struct
import binascii
import math

class Counter():
	TOTAL_LINES = 0x77
	CODE_FILEPOINTER = None




	#clear register
	def _0x100(self, key_buffer):
		self.writeQWord(key_buffer, 0x10, 0)
		return 0x11

	def _0x140(self, key_buffer):
		self.writeQWord(key_buffer, 0x10, 0)
		return 0x15

	def _0x1a0(self, key_buffer):
		self.writeQWord(key_buffer, 0x0, 0)
		return 0x1b

	def _0x1d0(self, key_buffer):
		self.writeQWord(key_buffer, 0x10, 0)
		return 0x1e

	def _0x1f0(self, key_buffer):
		self.writeQWord(key_buffer, 0x18, 0)
		return 0x20

	def _0x260(self, key_buffer):
		self.writeQWord(key_buffer, 0x8, 0)
		return 0x27

	def _0x2a0(self, key_buffer):
		self.writeQWord(key_buffer, 0x0, 0)
		return 0x2b

	def _0x2d0(self, key_buffer):
		self.writeQWord(key_buffer, 0x10, 0)
		return 0x2e

	def _0x330(self, key_buffer):
		self.writeQWord(key_buffer, 0x0, 0)
		return 0x34

	def _0x340(self, key_buffer):
		self.writeQWord(key_buffer, 0x8, 0)
		return 0x35

	def _0x410(self, key_buffer):
		self.writeQWord(key_buffer, 0x18, 0)
		return 0x42

	#def _0x490(self, key_buffer):
	#	self.writeQWord(key_buffer, 0x20, 0)
	#	return 0x4a

	def _0x500(self, key_buffer):
		self.writeQWord(key_buffer, 0x8, 0)
		return 0x51

	def _0x540(self, key_buffer):
		self.writeQWord(key_buffer, 0x0, 0)
		return 0x55

	def _0x570(self, key_buffer):
		self.writeQWord(key_buffer, 0x0, 0)
		return 0x58

	def _0x5c0(self, key_buffer):
		self.writeQWord(key_buffer, 0x0, 0)
		return 0x5d

	def _0x5d0(self, key_buffer):
		self.writeQWord(key_buffer, 0x8, 0)
		return 0x5e

	def _0x680(self, key_buffer):
		self.writeQWord(key_buffer, 0x8, 0)
		return 0x69

	def _0x6c0(self, key_buffer):
		self.writeQWord(key_buffer, 0x0, 0)
		return 0x6d

	def _0x740(self, key_buffer):
		self.writeQWord(key_buffer, 0x0, 0)
		return 0x75






	#copy from one register to another then clear
	def _0x0(self, key_buffer):
		value_0x0 = self.toQWord(key_buffer[0x0:0x0+8])
		value_0x8 = value_0x0
		if value_0x8 < 11:
			self.writeQWord(key_buffer, 0x00, 0)
			return 0x77
		
		total = 0
		i = value_0x8
		while(i >= 0):
			counter = 0
			testing_var = i
			while testing_var >= 2:
				if testing_var % 2 == 1:
					testing_var = (3 * testing_var) + 1
				else:
					testing_var = math.floor(testing_var/2)
				counter += 1
			total += counter
			i -= 1
		value_0x0 = total
		value_0x10 = value_0x0
		
		value_0x20 = self.fib(value_0x8)
		
		value_0x8 = value_0x20
		
		while True:
			if value_0x8 <= value_0x10: #0x640
				self.writeQWord(key_buffer, 0x00, value_0x8)
				return 0x77
			else:
				value_0x8 = value_0x8 - value_0x10
		
	def fib(self, value_0x8):
		if value_0x8 == 0:
			return 0
		elif value_0x8 == 1:
			return 1
		else:
			return self.fib(value_0x8 - 1) + self.fib(value_0x8 - 2)
		

	def _0x110(self, key_buffer):
		self.copyAndClearQwords(key_buffer, 0x10, 0x0)
		return 0x13

	def _0x160(self, key_buffer):
		self.copyAndClearQwords(key_buffer, 0x10, 0x0)
		return 0x18

	def _0x1b0(self, key_buffer):
		self.copyAndClearQwords(key_buffer, 0x0, 0x10)
		return 0x77

	def _0x200(self, key_buffer):
		self.copyAndClearQwords(key_buffer, 0x18, 0x0)
		return 0x22

	def _0x270(self, key_buffer):
		self.copyAndClearQwords(key_buffer, 0x8, 0x0)
		return 0x29

	def _0x2b0(self, key_buffer):
		self.copyAndClearQwords(key_buffer, 0x0, 0x10)
		return 0x77

	def _0x2f0(self, key_buffer):
		self.copyAndClearQwords(key_buffer, 0x10, 0x0)
		return 0x31

	def _0x350(self, key_buffer):
		self.copyAndClearQwords(key_buffer, 0x8, 0x10)
		return 0x37

	def _0x380(self, key_buffer):
		self.copyAndClearQwords(key_buffer, 0x10, 0x0)
		return 0x3a

	def _0x3b0(self, key_buffer):
		self.copyAndClearQwords(key_buffer, 0x0, 0x8)
		return 0x3d

	def _0x3d0(self, key_buffer):
		self.copyAndClearQwords(key_buffer, 0x0, 0x10)
		return 0x3f

	def _0x420(self, key_buffer):
		self.copyAndClearQwords(key_buffer, 0x18, 0x0)
		return 0x44

	def _0x4a0(self, key_buffer):
		self.copyAndClearQwords(key_buffer, 0x20, 0x0)
		return 0x4c

	#def _0x4e0(self, key_buffer):
	#	self.copyAndClearQwords(key_buffer, 0x20, 0x0)
	#	return 0x50

	def _0x510(self, key_buffer):
		self.copyAndClearQwords(key_buffer, 0x8, 0x20)
		return 0x53

	def _0x550(self, key_buffer):
		self.copyAndClearQwords(key_buffer, 0x0, 0x8)
		return 0x77

	def _0x580(self, key_buffer):
		self.copyAndClearQwords(key_buffer, 0x0, 0x8)
		return 0x5a

	def _0x5a0(self, key_buffer):
		self.copyAndClearQwords(key_buffer, 0x0, 0x10)
		return 0x77

	def _0x650(self, key_buffer):
		self.copyAndClearQwords(key_buffer, 0x0, 0x8)
		return 0x77

	def _0x690(self, key_buffer):
		self.copyAndClearQwords(key_buffer, 0x8, 0x0)
		return 0x6b

	def _0x750(self, key_buffer):
		self.copyAndClearQwords(key_buffer, 0x0, 0x8)
		return 0x77

	#key_buffer[0x0] = key_buffer[0x8] 
	def _0x1e0(self, key_buffer):
		self.copyQwords(key_buffer, 0x0, 0x8)
		return 0x1f

	def _0x2e0(self, key_buffer):
		self.copyQwords(key_buffer, 0x0, 0x8)
		return 0x2f

	def _0x370(self, key_buffer):
		self.copyQwords(key_buffer, 0x0, 0x8)
		return 0x38
		
	def _0x3a0(self, key_buffer):
		self.copyQwords(key_buffer, 0x0, 0x8)
		return 0x3b

	#def _0x400(self, key_buffer):
	#	self.copyQwords(key_buffer, 0x0, 0x8)
	#	return 0x41



		
	def _0x20(self, key_buffer):
		self.writeQWord(key_buffer, 0x10, 11)
		return 0x0d
		
	def _0xd0(self, key_buffer):
		value_0x8 = self.toQWord(key_buffer[0x8:0x8+8])
		value_0x10 = self.toQWord(key_buffer[0x10:0x10+8])
		print("key_buffer[0x0] = key_buffer[0x8] < key_buffer[0x10]")
		if value_0x8 < value_0x10:
			self.writeQWord(key_buffer, 0x0, 1)
		else:
			self.writeQWord(key_buffer, 0x0, 0)
		return 0x0e

	def _0xf0(self, key_buffer):
		print("""total = 0
i = key_buffer[0x8]
while(i >= 0):
	counter = 0
	testing_var = i
	while testing_var >= 2:
		if testing_var % 2 == 1:
			testing_var = 3 * testing_var) + 1
				else:
					testing_var = math.floor(testing_var/2)
				counter += 1
	total += counter
	i -= 1
key_buffer[0x0] = total""")
		total = 0
		i = self.toQWord(key_buffer[0x8:0x8+8])
		while(i >= 0):
			counter = 0
			testing_var = i
			while testing_var >= 2:
				if testing_var % 2 == 1:
					testing_var = (3 * testing_var) + 1
				else:
					testing_var = math.floor(testing_var/2)
				counter += 1
			total += counter
			i -= 1
		self.writeQWord(key_buffer, 0x00, total)
		return 0x10
		
		
	def _0x150(self, key_buffer):
		print("""counter = 0
testing_var = key_buffer[0x8]
while testing_var >= 2:
	if testing_var % 2 == 1:
		testing_var = 3 * testing_var) + 1
			else:
				testing_var = math.floor(testing_var/2)
			counter += 1
key_buffer[0x00] = counter""")
		counter = 0
		testing_var = self.toQWord(key_buffer[0x8:0x8+8])
		while testing_var >= 2:
			if testing_var % 2 == 1:
				testing_var = (3 * testing_var) + 1
			else:
				testing_var = math.floor(testing_var/2)
			counter += 1
		self.writeQWord(key_buffer, 0x00, counter)
		return 0x16

		
	def _0x240(self, key_buffer):
		print("WARNING - 0x240 is broken")
		print("key_buffer[0x0] = math.floor(key_buffer[0x8]/2)")
		key_buffer[0x0] = math.floor(key_buffer[0x8]/2)
		print("if key_buffer[0x8] mod 2 == 1: then (%s)" %(key_buffer[0x8] % 2 == 1))
		if key_buffer[0x8] % 2 == 0:
			return 0x25
		print("	key_buffer[0x0] = 3 * key_buffer[0x8] + 1")
		key_buffer[0x0] = 3 * key_buffer[0x8] + 1 
		return 0x25
		
	def _0x310(self, key_buffer):
		if self.toQWord(key_buffer[0x0:0x0+8]) != 0 | self.toQWord(key_buffer[0xc8:0xc8+8]) != 0:
			print("WARNING")
		
		self.writeQWord(key_buffer, 0x8, 0)
		
		print("key_buffer[0x0] = key_buffer[0x10]/2")
		value1 = self.toQWord(key_buffer[0x10:0x10+8])
		key_buffer[0x0:0x0+8] = struct.pack("<q", math.floor(value1/2))
		print("if key_buffer[0x10] % 2 == 1 (%s)" % (value1 % 2 == 1))
		if value1 % 2 == 1:
			print("key_buffer[0x8] = 1")
			key_buffer[0x8:0x8+8] = struct.pack("<q", 1)
		return 0x32

	def _0x630(self, key_buffer):
		value_0x8 = self.toQWord(key_buffer[0x8:0x8+8])
		value_0x10 = self.toQWord(key_buffer[0x10:0x10+8])
		print("key_buffer[0x0] = key_buffer[0x8] <= key_buffer[0x10]")		
		self.writeQWord(key_buffer, 0x00, value_0x8 <= value_0x10)
		return 0x64

	def _0x670(self, key_buffer):
		value_0x8 = self.toQWord(key_buffer[0x8:0x8+8])
		value_0x10 = self.toQWord(key_buffer[0x10:0x10+8])
		if value_0x10 > value_0x8:
			print("WARNING")
		print("key_buffer[0x0] = key_buffer[0x8] - key_buffer[0x10]")		
		self.writeQWord(key_buffer, 0x00, value_0x8 - value_0x10)
		return 0x68	

	def _0x130(self, key_buffer):
		print("""		self.writeQWord(key_buffer, 0x00, 0)

		key_0x8 = self.toQWord(key_buffer[0x8:0x8+8])
		key_0x20 = self.toQWord(key_buffer[0x20:0x20+8])

		if key_0x8 == 0:
			return 0x77
		elif key_0x8 == 1:
			self.writeQWord(key_buffer, 0x00, 1)
			return 0x77
		else:
			self.writeQWord(key_buffer, 0x00, 1)
			key_0x8 -= 1
			self.writeQWord(key_buffer, 0x08, key_0x8)
			#return 0x48
			new_buffer = key_buffer[:]
			self._0x400(new_buffer) #0x480
			key_buffer[0x0:0x8] = new_buffer[0x0:0x8]
			self.copyQwords(key_buffer, 0x20, 0x00)
			self.writeQWord(key_buffer, 0x00, 0)
			self.writeQWord(key_buffer, 0x08, self.toQWord(key_buffer[0x8:0x8+8]) - 1)
			new_buffer1 = key_buffer[:]
			self._0x400(new_buffer1) #at 0x4d0
			key_buffer[0x0:0x8] = new_buffer1[0x0:0x8]
			
			key_0x10 = self.toQWord(key_buffer[0x10:0x10+8])
			key_0x20 = self.toQWord(key_buffer[0x20:0x20+8])
			key_0x20 += self.toQWord(key_buffer[0x0:0x0+8])
			key_0x8 = key_0x20
			self.writeQWord(key_buffer, 0x8, key_0x8)
		
			while True:
				if key_0x8 <= key_0x10: #0x640
					self.writeQWord(key_buffer, 0x00, key_0x8)
					return 0x77
				else:
					key_0x8 = key_0x8 - key_0x10""")
		return self._0x400(key_buffer)
		
		
	def _0x400(self, key_buffer):
		self.writeQWord(key_buffer, 0x00, 0)

		key_0x8 = self.toQWord(key_buffer[0x8:0x8+8])
		key_0x20 = self.toQWord(key_buffer[0x20:0x20+8])

		if key_0x8 == 0:
			return 0x77
		elif key_0x8 == 1:
			self.writeQWord(key_buffer, 0x00, 1)
			return 0x77
		else:
			self.writeQWord(key_buffer, 0x00, 1)
			key_0x8 -= 1
			self.writeQWord(key_buffer, 0x08, key_0x8)
			#return 0x48
			new_buffer = key_buffer[:]
			self._0x400(new_buffer) #0x480
			key_buffer[0x0:0x8] = new_buffer[0x0:0x8]
			self.copyQwords(key_buffer, 0x20, 0x00)
			self.writeQWord(key_buffer, 0x00, 0)
			self.writeQWord(key_buffer, 0x08, self.toQWord(key_buffer[0x8:0x8+8]) - 1)
			new_buffer1 = key_buffer[:]
			self._0x400(new_buffer1) #at 0x4d0
			key_buffer[0x0:0x8] = new_buffer1[0x0:0x8]
			
			key_0x10 = self.toQWord(key_buffer[0x10:0x10+8])
			key_0x20 = self.toQWord(key_buffer[0x20:0x20+8])
			key_0x20 += self.toQWord(key_buffer[0x0:0x0+8])
			key_0x8 = key_0x20
			self.writeQWord(key_buffer, 0x8, key_0x8)
		
			while True:
				if key_0x8 <= key_0x10: #0x640
					self.writeQWord(key_buffer, 0x00, key_0x8)
					return 0x77
				else:
					key_0x8 = key_0x8 - key_0x10
		
	#def _0x490(self, key_buffer):
	#	self.copyQwords(key_buffer, 0x20, 0x00)
	#	self.writeQWord(key_buffer, 0x00, 0)
	#	self.writeQWord(key_buffer, 0x08, self.toQWord(key_buffer[0x8:0x8+8]) - 1)
	#	#self._0x400(new_buffer) #at 0x4d0
	#	#return 0x4d

	#def _0x4e0(self, key_buffer):
	#	key_0x10 = self.toQWord(key_buffer[0x10:0x10+8])
	#	key_0x20 = self.toQWord(key_buffer[0x20:0x20+8])
	#	key_0x20 += self.toQWord(key_buffer[0x0:0x0+8])
	#	key_0x8 = key_0x20
	#	self.writeQWord(key_buffer, 0x8, key_0x8)
	#	
	#	while True:
	#		if key_0x8 <= key_0x10: #0x640
	#			self.writeQWord(key_buffer, 0x00, key_0x8)
	#			return 0x77
	#		else:
	#			key_0x8 = key_0x8 - key_0x10

	optimizer = {
		#hand crafted optimizations
		0x20: _0x20,
		0xd0: _0xd0,
		0xf0: _0xf0,
		0x150: _0x150,
		0x1e0: _0x1e0,
		0x240: _0x240,
		0x2e0: _0x2e0,
		0x310: _0x310,
		0x370: _0x370,
		0x3a0: _0x3a0,
		0x130: _0x130,
		0x400: _0x400,
		#0x490: _0x490,
		#0x4e0: _0x4e0,
		0x630: _0x630,
		0x670: _0x670,

		#clear register
		0x100: _0x100,
		0x140: _0x140,
		0x1a0: _0x1a0,
		0x1d0: _0x1d0,
		0x1f0: _0x1f0,
		0x260: _0x260,
		0x2a0: _0x2a0,
		0x2d0: _0x2d0,
		0x330: _0x330,
		0x340: _0x340,
		0x410: _0x410,
		#0x490: _0x490,
		0x500: _0x500,
		0x540: _0x540,
		0x570: _0x570,
		0x5c0: _0x5c0,
		0x5d0: _0x5d0,
		0x680: _0x680,
		0x6c0: _0x6c0,
		0x740: _0x740,

		#copy from one register to another then clear
        	0x0: _0x0,
		0x110: _0x110,
		0x160: _0x160,
		0x1b0: _0x1b0,
		0x200: _0x200,
		0x270: _0x270,
		0x2b0: _0x2b0,
		0x2f0: _0x2f0,
		0x350: _0x350,
		0x380: _0x380,
		0x3b0: _0x3b0,
		0x3d0: _0x3d0,
		0x420: _0x420,
		0x4a0: _0x4a0,
		#0x4e0: _0x4e0,
		0x510: _0x510,
		0x550: _0x550,
		0x580: _0x580,
		0x5a0: _0x5a0,
		0x650: _0x650,
		0x690: _0x690,
		0x750: _0x750,


		
	 }
	
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

	def copyQwords(self, key_buffer, destination, source):
		sourceValue = self.toQWord(key_buffer[source:source+8])
		print("key_buffer[0x%x] = key_buffer[0x%x]" % (destination, source))
		key_buffer[destination:destination + 8] = struct.pack("<q", sourceValue)
		
	def addQWordsToDestination(self, key_buffer, destination, source):
		destinationValue = self.toQWord(key_buffer[destination:destination+8])
		sourceValue = self.toQWord(key_buffer[source:source+8])
		print("key_buffer[0x%x] += key_buffer[0x%x]" % (destination, source))
		key_buffer[destination:destination + 8] = struct.pack("<q", sourceValue + destinationValue)
	
	def copyAndClearQwords(self, key_buffer, destination, source):
		self.addQWordsToDestination(key_buffer, destination, source)
		print("key_buffer[0x%x] = 0" % (source))
		key_buffer[source:source + 8] = struct.pack("<q", 0)
		
	def writeQWord(self, key_buffer, destination, value):
		print("key_buffer[0x%x] = %s" % (destination, value))
		key_buffer[destination:destination+8] = struct.pack("<q", value)
	
	def counter(self, key_buffer, line_num):
		#print("starting counter, key = " + str(binascii.hexlify(key_buffer)))
		while line_num != self.TOTAL_LINES:
			current_line = line_num << 4
			headerByte = self.toDWord(self.CODE_FILEPOINTER[current_line:current_line+4])
			
			#print("(0x%x) - " % (current_line), end ="")
			
			#special cases
			if current_line in self.optimizer:
				#print("optimized -", end = "")
				line_num = self.optimizer[current_line](self, key_buffer)
				continue
				
			
			
			if headerByte == 0:
				#add 1 at key_address
				key_address = self.CODE_FILEPOINTER[current_line+4] * 8
				_temp = self.toQWord(key_buffer[key_address:key_address+8]) + 1
				self.packQWord(key_buffer, key_address, _temp)
				line_num = self.toDWord(self.CODE_FILEPOINTER[current_line+8:current_line+8+4])
				print("add 1, at = 0x%x, new_val = %s" % (key_address, _temp))
			if headerByte == 1:
				#subtract 1 at key_address if already zero then jump to different spot
				key_address = self.CODE_FILEPOINTER[current_line+4] * 8
				Qword_value = self.toQWord(key_buffer[key_address:key_address+8])
				if Qword_value != 0:
					Qword_value = Qword_value -1
					
					line_num = self.toDWord(self.CODE_FILEPOINTER[current_line+8:current_line+8+4])
					self.packQWord(key_buffer, key_address, Qword_value)
					print("sub 1, at = 0x%x, new_val = %s" % (key_address, Qword_value))
				else:
					line_num = self.toDWord(self.CODE_FILEPOINTER[current_line+12:current_line+12+4])
					print("zero , at = 0x%x, jumping" % (key_address))
			if headerByte == 2:
				#call counter from new_next_line copy result if firstDWord greater than zero
				new_buffer = key_buffer[:]
				new_next_line = self.toDWord(self.CODE_FILEPOINTER[current_line+8:current_line+8+4])
				firstQWord = self.toDWord(self.CODE_FILEPOINTER[current_line+4:current_line+4+4])
				thirdQWord = self.toDWord(self.CODE_FILEPOINTER[current_line+12:current_line+12+4])
				print("call , to = 0x%x and copy first = %s bytes. Return to = 0x%x" % (new_next_line, firstQWord, thirdQWord))
				self.counter(new_buffer, new_next_line)
				if firstQWord != 0:
					key_buffer[0:firstQWord*8] = new_buffer[0:firstQWord*8]
				line_num = self.toDWord(self.CODE_FILEPOINTER[current_line+12:current_line+12+4])
				
		#print("exiting counter, key = " + str(binascii.hexlify(key_buffer)))
					
					
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

