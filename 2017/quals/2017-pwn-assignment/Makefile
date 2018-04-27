build:
	gcc -Wall -O2 -fPIC -pie -Wl,-z,relro,-z,now -fstack-protector-all src/assignment.c src/str.c src/objects.c -o attachments/assignment
	strip -s attachments/assignment
