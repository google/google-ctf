import subprocess

for i in range(0,31):
	print(str(i) + " ", end="")
	print(subprocess.Popen(["../attachments/counter", str(i)], stdout=subprocess.PIPE).communicate()[0].decode("utf-8"), end="")

