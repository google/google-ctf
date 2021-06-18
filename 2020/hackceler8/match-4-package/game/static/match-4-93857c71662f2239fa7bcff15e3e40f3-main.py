import functools as f
a,b,c,d=input('> '),input('> '),input('> '),input('> ')
if int(a)==int(b)-1==int(c)-2==int(d)+-3:
    n=int(''.join(map(str,(a,b,c,d))))
    if f.reduce(lambda x,y:x*(int(''.join(map(str,(a,b,c,d))))%y),range(1,int(int(''.join(map(str,(a,b,c,d))))**.5)+1)):
        print('HCL8{The_m4gic_number_is_%d}'%(a**b*c**d))
