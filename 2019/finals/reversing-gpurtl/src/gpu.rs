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

use crate::config::Config;
use crate::glsl::lut::ty::Programming;
use crate::glsl::lut::BLOCK_SIZE;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use vulkano::buffer::{BufferSlice, CpuAccessibleBuffer, DeviceLocalBuffer, ImmutableBuffer};
use vulkano::command_buffer::AutoCommandBuffer;
use vulkano::command_buffer::AutoCommandBufferBuilder;
use vulkano::descriptor::descriptor_set::PersistentDescriptorSet;
use vulkano::device::{Device, Queue};
use vulkano::pipeline::ComputePipeline;
use vulkano::sync::GpuFuture;

pub struct GPU {
    device: Arc<Device>,
    queue: Arc<Queue>,
}

impl GPU {
    pub fn init() -> Self {
        use vulkano::instance::{Instance, InstanceExtensions};
        let instance =
            Instance::new(None, &InstanceExtensions::none(), None).expect("creating instance");

        use vulkano::instance::PhysicalDevice;
        let physical = PhysicalDevice::enumerate(&instance)
            .next()
            .expect("no device available");

        let queue_family = physical
            .queue_families()
            .find(|&q| q.supports_compute())
            .expect("finding a compute queue family");

        use vulkano::device::{DeviceExtensions, Features};
        let (device, mut queues) = Device::new(
            physical,
            &Features::none(),
            &DeviceExtensions::none(),
            [(queue_family, 0.5)].iter().cloned(),
        )
        .expect("creating device");

        let queue = queues.next().unwrap();

        GPU {
            device: device,
            queue: queue,
        }
    }
}

pub struct StateBuffer {
    buffer: Arc<DeviceLocalBuffer<[u32]>>,
    ports: Arc<BufferSlice<[u32], Arc<DeviceLocalBuffer<[u32]>>>>,
    state: Arc<BufferSlice<[u32], Arc<DeviceLocalBuffer<[u32]>>>>,
    block_offset: usize,
}

impl StateBuffer {
    pub fn new(gpu: &GPU, state_blocks: usize, port_size: usize) -> Self {
        use vulkano::buffer::BufferUsage;
        let usage = BufferUsage {
            storage_buffer: true,
            transfer_source: true,
            transfer_destination: true,
            ..BufferUsage::none()
        };

        let state_size = 2 * BLOCK_SIZE * state_blocks;
        let block_offset = port_size;
        let buffer_size = port_size + state_size;

        let buf = DeviceLocalBuffer::<[u32]>::array(
            gpu.device.clone(),
            buffer_size,
            usage,
            [gpu.queue.family()].iter().cloned(),
        )
        .expect("creating state buffer");

        use vulkano::buffer::BufferAccess;
        let ports = Arc::new(buf.clone().into_buffer_slice().slice(0..port_size).unwrap());
        let state = Arc::new(
            buf.clone()
                .into_buffer_slice()
                .slice(block_offset..buffer_size)
                .unwrap(),
        );

        Self {
            buffer: buf,
            ports,
            state,
            block_offset,
        }
    }

    pub fn size(&self) -> usize {
        use vulkano::buffer::TypedBufferAccess;
        self.buffer.len()
    }

    pub fn state_size(&self) -> usize {
        use vulkano::buffer::TypedBufferAccess;
        self.state.len()
    }
}

pub struct InputBuffer(Arc<CpuAccessibleBuffer<[u32]>>);

impl InputBuffer {
    pub fn new(gpu: &GPU, init: impl ExactSizeIterator<Item = bool>) -> Self {
        use vulkano::buffer::BufferUsage;
        let usage = BufferUsage {
            storage_buffer: true,
            transfer_source: true,
            ..BufferUsage::none()
        };

        let buf = CpuAccessibleBuffer::from_iter(gpu.device.clone(), usage, init.map(|x| x as u32))
            .expect("creating input buffer");
        Self(buf)
    }

    pub fn write<'a>(&'a self) -> impl DerefMut<Target = [u32]> + 'a {
        self.0.write().expect("write input buffer")
    }
}

pub struct OutputBuffer(Arc<CpuAccessibleBuffer<[u32]>>);

impl OutputBuffer {
    pub fn new(gpu: &GPU, size: usize) -> Self {
        use vulkano::buffer::BufferUsage;
        let usage = BufferUsage {
            storage_buffer: true,
            transfer_destination: true,
            ..BufferUsage::none()
        };

        let init = (0..size).map(|_| 0 as u32);
        let buf = CpuAccessibleBuffer::from_iter(gpu.device.clone(), usage, init)
            .expect("creating output buffer");
        Self(buf)
    }

    pub fn read<'a>(&'a self) -> impl Deref<Target = [u32]> + 'a {
        self.0.read().expect("read output buffer")
    }
}

pub struct ConfigBuffer(Arc<ImmutableBuffer<[Programming]>>);

impl ConfigBuffer {
    pub fn new(gpu: &GPU, config: &Config) -> Self {
        use vulkano::buffer::BufferUsage;
        let usage = BufferUsage {
            storage_buffer: true,
            ..BufferUsage::none()
        };

        let data: Vec<_> = config.data().copied().collect();

        let (buf, future) = ImmutableBuffer::from_iter(data.into_iter(), usage, gpu.queue.clone())
            .expect("creating config buffer");

        future
            .then_signal_fence_and_flush()
            .expect("flush config init")
            .wait(None)
            .expect("waiting for config init");

        Self(buf)
    }

    pub fn len(&self) -> usize {
        use vulkano::buffer::TypedBufferAccess;
        self.0.len()
    }

    pub fn blocks(&self) -> usize {
        use vulkano::buffer::TypedBufferAccess;
        self.0.len() / BLOCK_SIZE
    }
}

pub struct JumpBuffer(Arc<ImmutableBuffer<[u32]>>);

impl JumpBuffer {
    pub fn new(gpu: &GPU, config: &Config) -> Self {
        use vulkano::buffer::BufferUsage;
        let usage = BufferUsage {
            storage_buffer: true,
            ..BufferUsage::none()
        };

        let (buf, future) = ImmutableBuffer::from_iter(config.jumps(), usage, gpu.queue.clone())
            .expect("creating jumps buffer");

        future
            .then_signal_fence_and_flush()
            .expect("flush jumps init")
            .wait(None)
            .expect("waiting for jumps init");

        Self(buf)
    }

    pub fn len(&self) -> usize {
        use vulkano::buffer::TypedBufferAccess;
        self.0.len()
    }
}

pub struct Iteration {
    queue: Arc<Queue>,
    cmd: Arc<AutoCommandBuffer>,
    run_count: std::cell::Cell<u64>,
}

impl Iteration {
    pub fn run(&self) {
        use vulkano::command_buffer::CommandBuffer;
        let finished = self
            .cmd
            .clone()
            .execute(self.queue.clone())
            .expect("submitting command")
            .then_signal_fence_and_flush()
            .expect("signal fence and flush");
        finished.wait(None).expect("waiting for command finish");
        let run_count = self.run_count.get() + 1;
        self.run_count.replace(run_count);
    }

    pub fn iteration_count(&self) -> u64 {
        self.run_count.get()
    }
}

pub struct IterationBuilder<'a> {
    gpu: &'a GPU,
    state: &'a StateBuffer,
    cmd_builder: AutoCommandBufferBuilder,
}

impl<'a> IterationBuilder<'a> {
    pub fn new(gpu: &'a GPU, state: &'a StateBuffer) -> Self {
        let cmd_builder = AutoCommandBufferBuilder::primary(gpu.device.clone(), gpu.queue.family())
            .expect("creating primary buffer builder");
        Self {
            gpu: gpu,
            state: state,
            cmd_builder: cmd_builder,
        }
    }

    pub fn build(self) -> Iteration {
        Iteration {
            queue: self.gpu.queue.clone(),
            cmd: Arc::new(self.cmd_builder.build().expect("building command buffer")),
            run_count: std::cell::Cell::new(0),
        }
    }

    pub fn copy_ports_in(self, from: &InputBuffer) -> Self {
        Self {
            gpu: self.gpu,
            state: self.state,
            cmd_builder: self
                .cmd_builder
                .copy_buffer(from.0.clone(), self.state.ports.clone())
                .expect("copy port in buffer"),
        }
    }

    pub fn copy_state_out(self, to: &OutputBuffer) -> Self {
        Self {
            gpu: self.gpu,
            state: self.state,
            cmd_builder: self
                .cmd_builder
                .copy_buffer(self.state.state.clone(), to.0.clone())
                .expect("copy state out"),
        }
    }

    pub fn run_lut_cycles(self, config: &ConfigBuffer, jumps: &JumpBuffer, cycles: usize) -> Self {
        use crate::glsl::lut;
        let shader = lut::Shader::load(self.gpu.device.clone()).expect("creating shader");

        const INNER_CYCLES: u32 = 1;

        let mut cmd = self.cmd_builder;
        for _ in 0..cycles {
            let pipeline = Arc::new(
                ComputePipeline::new(
                    self.gpu.device.clone(),
                    &shader.main_entry_point(),
                    &lut::SpecializationConstants {
                        OFFSET: self.state.block_offset as u32,
                        CYCLES: INNER_CYCLES,
                        RISING_CLOCK: false as u32,
                    },
                )
                .expect("creating pipeline"),
            );

            let set = Arc::new(
                PersistentDescriptorSet::start(pipeline.clone(), 0)
                    .add_buffer(self.state.buffer.clone())
                    .expect("adding data buffer")
                    .add_buffer(config.0.clone())
                    .expect("adding config buffer")
                    .add_buffer(jumps.0.clone())
                    .expect("adding jumps buffer")
                    .build()
                    .expect("building descriptor set"),
            );

            cmd = cmd
                .dispatch(
                    [1, config.blocks() as u32, 1],
                    pipeline.clone(),
                    set.clone(),
                    (),
                )
                .expect("dispatch pipeline");
        }

        let pipeline = Arc::new(
            ComputePipeline::new(
                self.gpu.device.clone(),
                &shader.main_entry_point(),
                &lut::SpecializationConstants {
                    OFFSET: self.state.block_offset as u32,
                    CYCLES: 0 as u32,
                    RISING_CLOCK: true as u32,
                },
            )
            .expect("creating pipeline"),
        );

        let set = Arc::new(
            PersistentDescriptorSet::start(pipeline.clone(), 0)
                .add_buffer(self.state.buffer.clone())
                .expect("adding data buffer")
                .add_buffer(config.0.clone())
                .expect("adding config buffer")
                .add_buffer(jumps.0.clone())
                .expect("adding jumps buffer")
                .build()
                .expect("building descriptor set"),
        );

        cmd = cmd
            .dispatch(
                [1, config.blocks() as u32, 1],
                pipeline.clone(),
                set.clone(),
                (),
            )
            .expect("dispatch pipeline");

        Self {
            gpu: self.gpu,
            state: self.state,
            cmd_builder: cmd,
        }
    }
}
