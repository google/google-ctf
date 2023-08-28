from z3 import *

lines = open("circuit3-release.txt").readlines()

vs = {}

def get_var(i, j):
    if (i,j) not in vs:
        vs[i,j] = BitVec("v_%d_%d" % (i,j), 1)

    return vs[i,j]

inputs = []
s = Solver()

st = set()

#for i in range(len(lines)):
for i in range(40):
    if i % 10 == 0:
        print(i, "/", len(lines))
    for j in range(len(lines[i])):
        c = lines[i][j]
        st.add(c)
        if c == ' ' or c == "\n":
            has = False
            for ii in range(i-1, i+2):
                for jj in range(j-1, j+2):
                    if ii < 0 or ii >= len(lines): continue
                    if jj < 0 or jj >= len(lines[ii]): continue
                    if lines[ii][jj] not in " \n":
                        has = True
            if has:
                s.add(get_var(i, j) == 0)
        elif i == 23 and c == '9':
            inputs.append(get_var(i,j))
        elif c == '9':
            continue
        elif c == 'B':
            s.add(get_var(i,j) == 1)
        else:
            c = int(c)
            sm = BitVecVal(0, 4)
            for ii in range(i-1, i+2):
                for jj in range(j-1, j+2):
                    if ii == i and jj == j:
                        continue
                    sm = sm + ZeroExt(3, get_var(ii, jj))
            s.add(sm == c)

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
