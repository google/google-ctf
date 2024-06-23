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

import timeit
import numpy as np


def _mul_fast(a, b):
    if a == 0:
        return (0x10001 - b) & 0xffff
    if b == 0:
        return (0x10001 - a) & 0xffff
    c = a * b
    c0 = (c >> 32) & 0xffff
    ch = (c >> 16) & 0xffff
    cl = c & 0xffff
    if cl >= ch:
        return (cl - ch + c0) & 0xffff
    return (cl - ch + 2**16 + 1) & 0xffff


def _mul(x, y):
    if x == 0:
        x = 2**16
    if y == 0:
        y = 2**16
    z = x * y % (2**16 + 1)
    return z % 2**16


def benchmark(func, num_iterations=10000000):
    # Generate random input data
    inputs = np.random.randint(0, 2**16, (num_iterations, 2))

    # Time the function execution
    start_time = timeit.default_timer()
    for a, b in inputs:
        func(a, b)  # Call the function
    end_time = timeit.default_timer()

    # Calculate average time per iteration
    time_per_iteration = (end_time - start_time) / num_iterations
    return time_per_iteration


if __name__ == "__main__":
    original_time = benchmark(_mul)
    optimized_time = benchmark(_mul_fast)

    print(f"Original function time per iteration: {original_time:.10f} seconds")
    print(f"Optimized function time per iteration: {optimized_time:.10f} seconds")
    print(f"Speedup factor: {original_time / optimized_time:.2f}x")

