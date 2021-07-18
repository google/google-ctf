# Copyright 2021 Google LLC
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


all:
	python3 make_blueprint.py > /tmp/bp
	python3 compile_blueprint.py /tmp/bp > ../attachments/level2
	cp level1 game.py run.sh ../attachments
	chmod +x ../attachments/run.sh

# To solve the challenge, either run quicksolver (after generating maze files), or:
# python3 solver.py /tmp/solution 0110110100110001011100100100001001100101011010000101010000110010
# The latter takes many minutes to complete though, but it actually moves the cars,
# proof-checking the solution.
