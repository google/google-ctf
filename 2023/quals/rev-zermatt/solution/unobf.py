

o = open("replace.lua").readlines()
for line in o:
    line = line.rstrip("\n")
    while "some_string_obfusc(\"" in line:
        pref, mid = line.split("some_string_obfusc(", 1)
        mid, suf = mid.split(")", 1)
        first, second = mid.split(",")
        unobf = ""
        for c, d in zip(first[2:-1].split("\\"), second[2:-1].split("\\")*len(first)):
            unobf += chr(int(c)^int(d))
        line = pref + '"' + unobf + '"' + suf
    print(line)
