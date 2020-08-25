

all: out/sprint attachments/sprint

out/sprint.c: asm.py maze.s scaffold.c
	mkdir -p out
	python3 asm.py maze.s scaffold.c out/sprint.c

out/sprint: out/sprint.c
	gcc out/sprint.c -Wall -Wextra -Wno-restrict -Wno-format -o out/sprint
	#strip out/sprint

attachments/sprint: out/sprint
	mkdir -p attachments
	cp out/sprint attachments/sprint

test: out/sprint
	out/sprint <<< "ddrrrrrrddrrrrrrrrddllrruullllllllddddllllllddddrrrrrrrruurrddrrddrrlluulluullddlllllllluuuurrrrrruuuuuulllllldduurrrrrrddddddllllllddddrrrrrruuddlllllluuuuuurruuddllddrrrrrruuuurrrrrruurrllddllllllddddllllllddddrrddllrruulluuuurrrrrruullrruurruuuurrrrrr" | grep Flag

clean:
	rm -rf out
	rm -rf attachments

