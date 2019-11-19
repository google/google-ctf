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

use std::sync::Arc;
use vulkano::buffer::{BufferAccess, BufferInner, TypedBufferAccess};
use vulkano::device::{Device, DeviceOwned, Queue};
use vulkano::image::ImageAccess;
use vulkano::sync::AccessError;

pub struct DisjointBufferAccess<I>(I);

impl<I> DisjointBufferAccess<I> {
    pub unsafe fn new(inner: I) -> Self {
        Self(inner)
    }
}

unsafe impl<I: DeviceOwned> DeviceOwned for DisjointBufferAccess<I> {
    fn device(&self) -> &Arc<Device> {
        self.0.device()
    }
}

unsafe impl<I: BufferAccess> BufferAccess for DisjointBufferAccess<I> {
    fn inner(&self) -> BufferInner {
        self.0.inner()
    }
    fn size(&self) -> usize {
        self.0.size()
    }
    fn conflict_key(&self) -> (u64, usize) {
        self.0.conflict_key()
    }
    fn try_gpu_lock(&self, exclusive_access: bool, queue: &Queue) -> Result<(), AccessError> {
        self.0.try_gpu_lock(exclusive_access, queue)
    }
    unsafe fn increase_gpu_lock(&self) {
        self.0.increase_gpu_lock()
    }
    unsafe fn unlock(&self) {
        self.0.unlock()
    }

    fn conflicts_buffer(&self, _other: &dyn BufferAccess) -> bool {
        // HACKHACKHACK
        false
    }
    fn conflicts_image(&self, _other: &dyn ImageAccess) -> bool {
        // HACKHACKHACK
        false
    }
}

unsafe impl<I: TypedBufferAccess> TypedBufferAccess for DisjointBufferAccess<I> {
    type Content = I::Content;
}
