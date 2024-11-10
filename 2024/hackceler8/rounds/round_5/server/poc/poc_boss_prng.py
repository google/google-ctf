# Copyright 2024 Google LLC
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

# Semi-manual PoC:
# 1. In boss dialogue, set the max number to 4294967294
# 2. Set the number count to 624
# 3. Try a random guess (doesn't have to match the length you gave), e.g. "1"
# 4. From the output log, copy the comma-separated correct numbers of the boss into the field below.
# 5. Run this script with python3 -m poc.poc_boss_prng
# 6. Note the numbers printed at the end.
# 7. Talk to the boss again, set the max num to 100, number count to 10
# 8. Enter the numbers printed by this script.

import random, time
from poc.randcrack import RandCrack

rc = RandCrack()

boss_nums = "" # Add comma-separated numbers printed by boss here.
boss_nums = [int(i.strip()) for i in boss_nums.split(",")]
assert len(boss_nums) == 624
for num in boss_nums:
    rc.submit(num)

nums = [rc.predict_randint(0, 100) for i in range(10)]
print(nums)
