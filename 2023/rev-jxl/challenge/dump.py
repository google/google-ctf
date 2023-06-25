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

import numpy as np
import cv2

im = cv2.imread('flag.png', cv2.IMREAD_UNCHANGED)
im = cv2.cvtColor(im, cv2.COLOR_BGR2RGB)

im = im[:50, :50]

np.set_printoptions(linewidth=10000, threshold=10000000)
print()
print()
print(np.maximum(im[:, :, 0], im[:, :, 1]))
