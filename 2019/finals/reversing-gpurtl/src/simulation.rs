// Copyright 2019 Google LLC

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

const CYCLES: usize = 64;
const EXEC_FUNC_NAME: &str = "execute";

use crate::config::Config;
use crate::gpu::{
    ConfigBuffer, InputBuffer, Iteration, IterationBuilder, JumpBuffer, OutputBuffer, StateBuffer,
    GPU,
};
use crate::util::{bitstream_to_bytes, bytes_to_bitstream};
use rlua::prelude::*;

pub struct Simulation {
    input: InputBuffer,
    output: OutputBuffer,
    iter: Iteration,
    lua: Lua,
}

impl Simulation {
    pub fn init(config: &Config, script: impl AsRef<[u8]>) -> Self {
        let gpu = GPU::init();

        use crate::util::IteratorExtensions;
        let port_init = std::iter::repeat(false).take_pad(config.port_bits(), false);

        let state = StateBuffer::new(&gpu, config.size_blocks(), config.port_bits());
        let port_in = InputBuffer::new(&gpu, port_init);
        let port_out = OutputBuffer::new(&gpu, state.state_size());
        let config_buf = ConfigBuffer::new(&gpu, &config);
        let jumps = JumpBuffer::new(&gpu, &config);

        let iter = IterationBuilder::new(&gpu, &state)
            .copy_ports_in(&port_in)
            .run_lut_cycles(&config_buf, &jumps, CYCLES)
            .copy_state_out(&port_out)
            .build();

        let lua = Lua::new();
        lua.context(|ctx| ctx.load(&script).exec().expect("failed to eval script"));

        Self {
            input: port_in,
            output: port_out,
            iter,
            lua,
        }
    }

    pub fn execute(&self) -> Result<(), LuaError> {
        self.lua.context(|ctx| {
            ctx.scope(|scope| {
                let sim = scope.create_nonstatic_userdata(self)?;

                ctx.globals()
                    .get::<_, LuaFunction>(EXEC_FUNC_NAME)?
                    .call::<LuaAnyUserData, ()>(sim)
            })
        })
    }
}

impl LuaUserData for &Simulation {
    fn add_methods<'lua, M: LuaUserDataMethods<'lua, Self>>(m: &mut M) {
        m.add_method("read_output_bytes", |_, sim, bits: Vec<usize>| {
            let r = sim.output.read();
            let b: Vec<u8> = bitstream_to_bytes(bits.iter().map(|b| r[*b] == 1)).collect();
            Ok(b)
        });
        m.add_method("read_output_bit", |_, sim, bit: usize| {
            let r = sim.output.read();
            Ok(r[bit] == 1)
        });

        m.add_method(
            "write_input_bytes",
            |_, sim, (bits, data): (Vec<usize>, Vec<u8>)| {
                let mut w = sim.input.write();
                bytes_to_bitstream(data)
                    .zip(bits)
                    .for_each(|(d, b)| w[b] = d as u32);
                Ok(())
            },
        );
        m.add_method("write_input_bit", |_, sim, (bit, val): (usize, bool)| {
            let mut w = sim.input.write();
            w[bit] = val as u32;
            Ok(())
        });

        m.add_method("iteration_count", |_, sim, ()| {
            Ok(sim.iter.iteration_count())
        });
        m.add_method("run", |_, sim, ()| Ok(sim.iter.run()));
    }
}
