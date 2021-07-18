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

echo "Welcome to our game. You need to enter the red vehicle into a crowded parking lot."
echo "There are two levels: the first is introductory, just so you know the rules; the second, when solved, will reveal the flag. Good luck!"
FLAG=0 python3 game.py level1
echo "Good job! Now that you know the rules, let's move to the real level. Note that it is quite large, so allow some loading time."
python3 game.py level2
