prisonbreak: solution.c solution2.c
	$(CC) -std=c99 solution2.c -o sol2
	xxd -i sol2 solution2.inc
	$(CC) -std=c99 solution.c -fPIC -o sol

exec: prisonbreak
	python ./client.py

clean:
	rm sol sol2
