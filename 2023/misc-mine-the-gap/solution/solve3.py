


lines = open("result").read()

lines = lines.replace("AND", "A--")
lines = lines.replace("XOR", "X--")
lines = lines.replace("OR", "O-")
lines = lines.replace("INPUT", "  I  ")
lines = lines.replace("==", "--")
lines = lines.replace("I?", "  ")
lines = lines.replace("=", " ")

open("res3", "w").write(lines)

