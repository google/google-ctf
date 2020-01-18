#!/usr/bin/env python2.7
from __future__ import print_function
import sys, random, string, struct
from hashlib import sha256

def proof_of_work_okay(chall, solution, hardness):
    h = sha256(chall.encode('ASCII') + struct.pack('<Q', solution)).hexdigest()
    return int(h, 16) < 2**256 / hardness

def random_string(length = 10):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def solve_proof_of_work(task):
    hardness, task = task.split('_')
    hardness = int(hardness)

    ''' You can use this to solve the proof of work. '''
    print('Creating proof of work for {} (hardness {})'.format(task, hardness))
    i = 0
    while True:
        if i % 1000000 == 0: print('Progress: %d' % i)
        if proof_of_work_okay(task, i, hardness):
            return i
        i += 1

if __name__ == '__main__':
    if sys.version[0] == '2':
        input = raw_input

    if len(sys.argv) > 1 and sys.argv[1] == 'ask':
        hardness = int(sys.argv[2])

        challenge = random_string()
        print()
        print(' ======================================')
        print(' Proof of work code & solver can be found at https://35c3ctf.ccc.ac/uploads/pow.py')
        print(' You may run the following to solve:')
        print()
        print('    ./pow.py {}_{}'.format(hardness, challenge))
        print(' ======================================')
        print()

        print('Proof of work challenge: {}_{}'.format(hardness, challenge))
        sys.stdout.write('Your response? ')
        sys.stdout.flush()
        sol = int(input())
        if not proof_of_work_okay(challenge, sol, hardness):
            print('Wrong :(')
            exit(1)
    else:
        if len(sys.argv) > 1:
            challenge = sys.argv[1]
        else:
            sys.stdout.write('Challenge? ')
            sys.stdout.flush()
            challenge = input()
        print('Solution: {}'.format(solve_proof_of_work(challenge)))
