from z3 import *

lines = open("res3").readlines()

vs = {}

def get_var(i, j):
    if (i,j) not in vs:
        vs[i,j] = BitVec("v_%d_%d" % (i,j), 1)

    return vs[i,j]

inputs = []
s = Solver()

st = set()

for i in range(len(lines)):
    if i % 100 == 0:
        print(i, "/", len(lines))
    for j in range(len(lines[i])):
        c = lines[i][j]
        st.add(c)
        if c == ' ' or c == "\n":
            continue
        elif c == "I":
            inputs.append(get_var(i,j))
        elif c == "|":
            if lines[i-1][j] in "I-+|1":
                s.add(get_var(i,j) == get_var(i-1,j))
            if lines[i+1][j] in "I-+|1":
                s.add(get_var(i,j) == get_var(i+1,j))
        elif c == "-":
            if lines[i][j-1] in "I-+|1":
                s.add(get_var(i,j) == get_var(i,j-1))
            if lines[i][j+1] in "I-+|1":
                s.add(get_var(i,j) == get_var(i,j+1))
        elif c == "+":
            s.add(get_var(i,j) == get_var(i-1,j))
            s.add(get_var(i,j) == get_var(i+1,j))
            s.add(get_var(i,j) == get_var(i,j-1))
            s.add(get_var(i,j) == get_var(i,j+1))
        elif c == ">":
            s.add(get_var(i,j) == get_var(i,j+1))
            s.add(get_var(i,j) == get_var(i-1,j))
            s.add(get_var(i,j) == get_var(i+1,j))
        elif c == "<":
            s.add(get_var(i,j) == get_var(i,j-1))
            s.add(get_var(i,j) == get_var(i-1,j))
            s.add(get_var(i,j) == get_var(i+1,j))
        elif c == "H":
            s.add(get_var(i+1,j) == get_var(i-1,j))
            s.add(get_var(i,j+1) == get_var(i,j-1))
        elif c == "N":
            s.add(get_var(i+1,j) != get_var(i-1,j))
            s.add(get_var(i,j+1) != get_var(i,j-1))
        elif c == "A":
            s.add(get_var(i,j+1) == (get_var(i-1,j) & get_var(i+1,j)))
        elif c == "O":
            s.add(get_var(i,j+1) == (get_var(i-1,j) | get_var(i,j-1)))
        elif c == "X":
            s.add(get_var(i,j+1) == (get_var(i-1,j) ^ get_var(i,j-1)))
        elif c == "1":
            s.add(get_var(i,j) == 1)
        else:
            print(c)
            asd

print(st)
cnt = 0
while s.check():
    m = s.model()
    res = ""
    for i in inputs:
        res += str(m[i])
    print(cnt, res)
    cnt += 1
    s.add(Or([m[i] != i for i in inputs]))
