

s = open("orig.lua").read()
s = "\n".join(s.split(";"))
if 1:
    s = s.replace("end ", "end\n")
    s = s.replace("then ", "then\n")
    s = s.replace("do ", "do\n")
    s = s.replace("local", "\nlocal")
    s = s.replace("\n\n", "\n")
    #s = s.replace("if", "\nif")
    #s = s.replace("\n\n", "\n")
print(s)

