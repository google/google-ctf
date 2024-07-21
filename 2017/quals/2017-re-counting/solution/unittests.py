from counter_new import Counter
import sys
import struct
import binascii
import math


resultsfile = open("results.txt")

for line in resultsfile:
	case = line.split(" ")
	input_val = int(case[0])
	output_val = case[1][:-1]


	count = Counter()
	count.init()

	input_value = input_val
	key = bytearray(struct.pack("<q", input_value)) + bytearray([0]*200)
	count.counter(key, 0)
	result = str(hex(struct.unpack("<q", key[0:8])[0]))[2:]
	if len(result) < 16:
		result = "0"*(16-len(result)) + result

	actual_output = "CTF{" + result + "}"
	print("actual = '" + actual_output + "' expected = '" + str(output_val) + "' matches = " + str(actual_output == str(output_val)))
