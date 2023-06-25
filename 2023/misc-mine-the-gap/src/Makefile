# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

dev:
	FLASK_APP=dev-server.py FLASK_ENV=debug FLASK_DEBUG=true flask run

schematic.svg: schematic.json
	netlistsvg schematic.json -o schematic.svg

schematic.dot schematic.json: schematic.v
	yosys -p "synth -top Challenge; abc -g OR,XOR,AND; write_json schematic.json; show -stretch -prefix schematic -format dot" schematic.v

schematic2.svg: schematic.dot
	dot -Tsvg -oschematic2.svg schematic.dot

circuit3-release.txt circuit3-debug.txt: generate_circuit3.py schematic.json
	python3 generate_circuit3.py circuit3

clean:
	rm -f schematic.json schematic.svg schematic2.svg schematic.dot circuit2.txt

.PHONY: dev clean
