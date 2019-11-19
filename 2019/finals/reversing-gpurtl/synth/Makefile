autogen/%.blif: design/%.v synth.yosys
	cp -f "$<" /tmp/synth.v
	yosys -s synth.yosys
	rm -f /tmp/synth.v
	mv /tmp/synth.blif "$@"

autogen/%.bin autogen/%.portmap: autogen/%.blif place.py arch.py blif.py
	cp -f "$<" /tmp/synth.blif
	pipenv run python place.py
	rm -f /tmp/synth.blif
	mv /tmp/synth.bin autogen/"$*".bin
	mv /tmp/synth.portmap autogen/"$*".portmap
