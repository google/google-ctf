#!/usr/bin/python3 -u

SBOX = {
    (0, 0): (0, 0),
    (0, 1): (1, 0),
    (0, 2): (0, 1),
    (1, 0): (1, 1),
    (1, 1): (0, 2),
    (1, 2): (1, 2),
}


def step(l1, l2):
    if l1[0] == 0:
        l1.pop(0)
    else:
        l2.insert(0, 1)
    l1.append(0)

    for i in range(len(l1)):
        l1[i], l2[i] = SBOX[l1[i], l2[i]]

    while l1[-1] == l2[-1] == 0:
        l1.pop()
        l2.pop()


def count(l1, l2):
    n = 0
    while l1 + l2 != [1, 0]:
        step(l1, l2)
        n += 1
    return n


def read_lists():
    l1 = [ord(c) % 2 for c in input("> ")]
    l2 = [ord(c) % 3 for c in input("> ")]
    assert len(l1) < 24, "too big"
    assert len(l1) == len(l2), "must be same size"
    return l1, l2


if __name__ == "__main__":
    l1, l2 = read_lists()
    c = count(l1, l2)
    if c > 2000:
        print("You win")
        print(open("flag.txt").read())
    else:
        print("Too small :(")
        print(c)
