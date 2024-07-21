file = open("code_hex.txt")
content = file.readlines()[0]

instructions = {}

curser = 0
while curser <= 2 * 0x760:
	pc = int(curser/2)
	command = int(content[curser+(0*8):curser+(1*8)][:2], 16)
	arg1 = int(content[curser+(1*8):curser+(2*8)][:2], 16) * 8
	arg2 = int(content[curser+(2*8):curser+(3*8)][:2], 16)
	arg3 = int(content[curser+(3*8):curser+(4*8)][:2], 16)
	
	instructions[pc] = {
	'pc': pc, 
	'command': command, 
	'arg1': arg1, 
	'arg2': arg2, 
	'arg3': arg3}
	
	#if instruction == 1 and arg2<<4 == pc+16:
	#	#print("		0x%x: _0x%x," % (pc, pc))
	#	print("(0x%x) %s - 0x%x, 0x%x, 0x%x" % (pc, instruction, arg1, arg2, arg3))
	curser += 32
	
	#1. compaire
	#2. assign value
	
#print(instructions)
for key in instructions:
	pc = instructions[key]['pc']
	command = instructions[key]['command']
	arg1 = instructions[key]['arg1']
	arg2 = instructions[key]['arg2']
	arg3 = instructions[key]['arg3']
	
	if command == 1 and arg2<<4 < 0x770:
		if instructions[arg2<<4]['command'] == 0 and instructions[arg2<<4]['arg2']<<4 == pc:
			#print("(0x%x) %s - 0x%x, 0x%x, 0x%x" % (pc, command, arg1, arg2, arg3))
			print("		0x%x: _0x%x," % (pc, pc))
			
			
			
			
			
			
			
			
			
			
