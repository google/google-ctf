with open('./flag') as f:
    flag = f.read().strip()

print('''
  ________                                         .__                 ______
 /  _____/ __ __   ____   ______ ______ ____  ____ |  |   ___________ /  __  \ 
/   \  ___|  |  \_/ __ \ /  ___//  ___// ___\/ __ \|  | _/ __ \_  __ \>      <
\    \_\  \  |  /\  ___/ \___ \ \___ \\\\  \__\  ___/|  |_\  ___/|  | \/   --   \ 
 \______  /____/  \___  >____  >____  >\___  >___  >____/\___  >__|  \______  /
        \/            \/     \/     \/     \/    \/          \/             \/ 

        — Can you guess the flag?
''')

guess = ''
while guess != flag:
    guess = input('> ')
    if len(guess) != len(flag):
        print('Invalid length.')
        continue
    out = ''
    for j,k in zip(guess, flag):
        if j == k:
            out += j
        elif j in flag:
            out += '*'
        else:
            out += '.'
    print(out)
print('%s is the correct flag.' % flag)

