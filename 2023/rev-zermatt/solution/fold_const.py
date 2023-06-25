import re

test= "elseif (v146==(701 -(208 + 490))) then"

if 1:
    s = open("string_deobf.lua").readlines()

    done = False
    for line in s:
        line = line.rstrip("\n")
        while 1:
            r = re.search(r"\b(\d+) *\^ *(\d+)\b", line)
            if r:
                line = line[:r.start()] + str(int(r.group(1)) ** int(r.group(2))) + line[r.end():]
                done = True
                continue
            r = re.search(r"\b(\d+) *\+ *(\d+)\b", line)
            if r:
                line = line[:r.start()] + str(int(r.group(1)) + int(r.group(2))) + line[r.end():]
                done = True
                continue
            r = re.search(r"\b(\d+) *\- *(\d+)\b", line)
            if r:
                line = line[:r.start()] + str(int(r.group(1)) - int(r.group(2))) + line[r.end():]
                done = True
                continue
            r = re.search(r"([-+^*] *)\( *(\d+) *\)", line)
            if r:
                line = line[:r.start()] + r.group(1) + r.group(2) + line[r.end():]
                done = True
                continue
            r = re.search(r"\( *(\d+) *\)( *[-+^*])", line)
            if r:
                line = line[:r.start()] + r.group(1) + r.group(2) + line[r.end():]
                done = True
                continue
            break
        print(line)

