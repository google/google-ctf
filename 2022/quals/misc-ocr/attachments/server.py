# Copyright 2022 Google LLC
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
import sys
import glob
import string
import tensorflow as tf
from keras.models import Sequential
from keras.layers.core import Dense, Flatten
from flag import flag
import signal

signal.alarm(120)

tf.compat.v1.disable_eager_execution()

image_data = []
for f in sorted(glob.glob("images/*.png")):
    im = tf.keras.preprocessing.image.load_img(
        f, grayscale=False, color_mode="rgb", target_size=None, interpolation="nearest"
    )
    im = tf.keras.preprocessing.image.img_to_array(im)
    im = im.astype("float32") / 255
    image_data.append(im)

image_data = np.array(image_data, "float32")

# The network is pretty tiny, as it has to run on a potato.
model = Sequential()
model.add(Flatten(input_shape=(16,16,3)))
# I'm sure we can compress it all down to four numbers.
model.add(Dense(4, activation='relu'))
model.add(Dense(128, activation='softmax'))

print("Train this neural network so it can read text!")

wt = model.get_weights()
while True:
    print("Menu:")
    print("0. Clear weights")
    print("1. Set weight")
    print("2. Read flag")
    print("3. Quit")
    inp = int(input())
    if inp == 0:
        wt[0].fill(0)
        wt[1].fill(0)
        wt[2].fill(0)
        wt[3].fill(0)
        model.set_weights(wt)
    elif inp == 1:
        print("Type layer index, weight index(es), and weight value:")
        inp = input().split()
        value = float(inp[-1])
        idx = [int(c) for c in inp[:-1]]
        wt[idx[0]][tuple(idx[1:])] = value
        model.set_weights(wt)
    elif inp == 2:
        results = model.predict(image_data)
        s = ""
        for row in results:
            k = "?"
            for i, v in enumerate(row):
                if v > 0.5:
                    k = chr(i)
            s += k
        print("The neural network sees:", repr(s))
        if s == flag:
            print("And that is the correct flag!")
    else:
        break
