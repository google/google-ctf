

bits1 = "1101101101010010101011101111010100100001011111110111100111011000000101110011110001011010001110111111001101110111011011111111"

bits1 = [int(c) for c in bits1]
print(bits1)

with open('circuit3-release.txt', 'r') as fin:
    circuit = fin.read()
    circuit = circuit.replace(' ', '0')
    circuit = [list(line) for line in circuit.split('\n') if len(line) > 0]

GRID_WIDTH = len(circuit[0])

bits = []
k = 0
for x in range(GRID_WIDTH):
    bit = 0
    print(x)
    if circuit[23][x] == '9':
        bit = 1-bits1[k]
        k += 1
    bits.append(bit)


import hashlib

flag = hashlib.sha256(bytes(bits)).hexdigest()
print(f'Flag: CTF{{{flag}}}')
