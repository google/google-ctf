.ONESHELL:

.PHONY: clean all run attachments

all: simavr/examples/board_i2ctest/obj-x86_64-linux-gnu/matter.elf attachments

simavr/examples/board_i2ctest/obj-x86_64-linux-gnu/matter.elf:
	git clone https://github.com/buserror/simavr.git
	cd simavr
	git checkout ba721226ba869e7a1a168686cf53d4efefa4e439
	git apply ../simavr_diff
	make

clean:
	rm -rf simavr
	rm -rf ../attachments
	rm -rf ../chroot

attachments: simavr/examples/board_i2ctest/obj-x86_64-linux-gnu/matter.elf simavr_diff
	strip -R .comment simavr/examples/board_i2ctest/obj-x86_64-linux-gnu/matter.elf
	install -pD -m644 debugger.py ../attachments/debugger.py
	install -pD -m644 simavr/examples/board_i2ctest/atmega2560_matter.axf ../attachments/matter.axf
	install -pD -m755 simavr/examples/board_i2ctest/obj-x86_64-linux-gnu/matter.elf ../attachments/matter-sim
	install -pD -m644 simavr_diff ../attachments/simavr_diff
	install -pD -m644 simavr/examples/board_i2ctest/atmega2560_matter.axf ../chroot/matter.axf
	install -pD -m755 simavr/examples/board_i2ctest/obj-x86_64-linux-gnu/matter.elf ../chroot/bin/matter-sim

run: all
	nsjail -Ml --port 1337 --chroot $(PWD)/../chroot --user 99999 --group 99999 --rlimit_cpu 10 -t 1800 --rlimit_as 512 --rlimit_nofile 32 -- /bin/matter-sim /matter.axf
