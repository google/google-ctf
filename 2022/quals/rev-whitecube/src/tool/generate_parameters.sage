#!/usr/bin/env sage

def print_glsl_mat16(matrix):
    mat4s = []
    for y in range(4):
        for x in range(4):
            submatrix = matrix.matrix_from_rows_and_columns(list(range(4*y, 4*(y+1))), list(range(4*x, 4*(x+1))))
            submatrix = submatrix.transpose().list()
            submatrix = ', '.join(f'{int(x):.1f}' for x in submatrix)
            mat4s.append(f'mat4({submatrix})')
    print(',\n'.join(mat4s))

def generate_diffusion_matrix(Fm):
    while True:
        try:
            D = Fm.random_element()
            Dinv = D.inverse()
            break
        except:
            pass

    return D

F = Integers(256)
Fm = MatrixSpace(F, 16, 16)    

D = generate_diffusion_matrix(Fm)
k0 = Fm.random_element()
k1 = Fm.random_element()
k2 = Fm.random_element()

a = identity_matrix(F, 16)
for i in range(16):
    a[i,i] = 2*randint(1,128)-1
a.inverse()


print('# Solver')
print(f'D = {D.list()}')
print(f'k0 = {k0.list()}')
print(f'k1 = {k1.list()}')
print(f'k2 = {k2.list()}')

print('# GLSL')

print('const mat4 diffusion[16] = mat4[](')
print_glsl_mat16(D)
print(');')

print('const mat4 k0[16] = mat4[](')
print_glsl_mat16(k0)
print(');')

print('const mat4 k1[16] = mat4[](')
print_glsl_mat16(k1)
print(');')

print('const mat4 k2[16] = mat4[](')
print_glsl_mat16(k2)
print(');')
