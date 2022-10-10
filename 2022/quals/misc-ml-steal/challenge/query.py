# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#!/usr/bin/python3

import sys
import gzip
import pickle
import numpy as np

# Import our fancy neural network
from mlsteal import sample


if __name__ == "__main__":
    # Load the model weights
    weights = np.frombuffer(gzip.open("weights.gz","rb").read(), dtype=np.float32)

    # Get model prompt from first argument
    if len(sys.argv) == 1:
        print("Please pass one argument containing a string to prompt the language model")
        exit(1)
    prompt = bytes(sys.argv[1],'ascii')
    x = np.array(list(prompt), dtype=np.uint64)

    # Run neural network on the prompt
    y = sample(x, weights)

    # Print to stdout
    print(b"".join(np.array(sample(x, weights),dtype=np.uint8)))
