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


s = """3
copy1_u1^ copy0_u7 clk^
3
copy1_u2^ copy0_u8^ clk^
3
copy1_u3 copy1_u1^ copy1_u4^
3
copy1_u4^ copy1_u3 copy1_u2^
3
copy1_u9 copy1_u3 copy1_u3
3
copy1_u5^ copy1_u3 nclk
3
copy1_u6 copy1_u9 nclk
3
copy1_u7 copy1_u5^ copy1_u8^
3
copy1_u8^ copy1_u7 copy1_u6"""

for i in range(20):
  print(s.replace("copy1", "copy%d" % (i+1)).replace("copy0", "copy%d" % i))
