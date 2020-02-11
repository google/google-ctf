# Output files should go to ../files

../../.gen/src: ../files/shell
	touch $@

../files/shell: shell.c
	$(CC) -o $@ $<
