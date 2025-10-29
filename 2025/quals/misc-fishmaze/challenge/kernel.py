# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import jax
from jax import lax, export
import jax.numpy as jnp
from jax.experimental import pallas as pl
from jax.experimental.pallas import tpu as pltpu
import sys

AUX_SIZE = 64
in_shape = (8,)
out_shape = (1 + AUX_SIZE,)
aux_shape = (AUX_SIZE,)

# INSERT USER CODE HERE

def player(mapdata, aux_data):
    jax_player = pl.pallas_call(
        player_kernel,
        out_shape=jax.ShapeDtypeStruct(out_shape, mapdata.dtype),
        grid=(1,),
        out_specs=pl.BlockSpec(
            out_shape, index_map=lambda _: (0,), memory_space=pltpu.SMEM),
        in_specs=[
            pl.BlockSpec(
                in_shape, index_map=lambda _: (0,), memory_space=pltpu.SMEM),
            pl.BlockSpec(
                aux_shape, index_map=lambda _: (0,), memory_space=pltpu.SMEM)
        ],
        interpret=True)
    return jax_player(mapdata, aux_data)

nearby_cells_array = jnp.zeros(in_shape, dtype=jnp.int32)
aux_data = jnp.zeros(aux_shape, dtype=jnp.int32)
exported_kernel = export.export(jax.jit(player)) (nearby_cells_array, aux_data)
serialized: bytearray = exported_kernel.serialize()
sys.stdout.buffer.write(serialized)
