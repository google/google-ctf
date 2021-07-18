// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
extern crate errno;
use errno::errno;

extern crate lazy_static;
use lazy_static::lazy_static;

extern crate riscv_emu_rust;
use riscv_emu_rust::{terminal::Terminal, Emulator, GuestPCIDevice, GuestPCIDevices};

extern crate libvfio_user_sys;
use libvfio_user_sys::*;

use std::ffi::CString;
use std::os::raw::*;

use std::sync::{Arc, Mutex};

use std::io::Write;

pub struct DebugTerminal {}

impl DebugTerminal {
    pub fn new() -> Self {
        DebugTerminal {}
    }
}

impl Terminal for DebugTerminal {
    fn put_byte(&mut self, value: u8) {
        std::io::stdout().lock().write(&[value]).unwrap();
    }

    fn get_input(&mut self) -> u8 {
        0
    }
    fn put_input(&mut self, _value: u8) {}
    fn get_output(&mut self) -> u8 {
        0
    }
}

fn do_irq(dev: &GuestPCIDevice) {
    if let Some(vfu_ctx) = dev.ctx {
        unsafe {
            vfu_irq_trigger(vfu_ctx as *mut vfu_ctx_t, 0);
        }
    }
}

lazy_static! {
    static ref GUEST_PCI_DEVICES: GuestPCIDevices = Arc::new([
        Mutex::new(GuestPCIDevice::with_irq_fn(do_irq)),
        Mutex::new(GuestPCIDevice::with_irq_fn(do_irq)),
    ]);
}

lazy_static! {
    static ref PCI_RAW_MEMORY: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(vec![0u8; 2 * 0x1000]));
}

extern "C" fn dma_register(_vfu_ctx: *mut vfu_ctx_t, _vfu_dma_info: *mut vfu_dma_info_t) {}

extern "C" fn dma_unregister(_vfu_ctx: *mut vfu_ctx_t, _vfu_dma_info: *mut vfu_dma_info_t) -> i32 {
    0
}

extern "C" fn bar2_access(
    vfu_ctx: *mut vfu_ctx_t,
    buf: *mut c_char,
    count: u64,
    offset: i64,
    is_write: bool,
) -> ssize_t {
    std::panic::catch_unwind(|| {
        let idx = unsafe { vfu_get_private(vfu_ctx) } as *mut usize as *const usize;
        let idx = unsafe { *idx };
        let mut device = GUEST_PCI_DEVICES[idx].lock().unwrap();
        //println!("[idx={}] Access [w={}] off={} count={}", idx, is_write, offset, count);
        if is_write {
            let buf = unsafe { std::slice::from_raw_parts(buf as *const u8, count as usize) };
            for i in 0..count {
                device.memory[offset as usize + i as usize] = buf[i as usize];
            }
            count as i64
        } else {
            let buf = unsafe { std::slice::from_raw_parts_mut(buf as *mut u8, count as usize) };
            for i in 0..count {
                buf[i as usize] = device.memory[offset as usize + i as usize];
            }
            count as i64
        }
    })
    .unwrap_or(0)
}

extern "C" fn migration_device_state_transition(
    _vfu_ctx: *mut vfu_ctx_t,
    _state: vfu_migr_state_t,
) -> c_int {
    0
}

extern "C" fn migration_get_pending_bytes(_vfu_ctx: *mut vfu_ctx_t) -> u64 {
    0
}

extern "C" fn migration_prepare_data(
    _vfu_ctx: *mut vfu_ctx_t,
    _offset: *mut u64,
    _size: *mut u64,
) -> c_int {
    0
}

extern "C" fn migration_read_data(
    _vfu_ctx: *mut vfu_ctx_t,
    _buf: *mut c_void,
    _count: u64,
    _offset: u64,
) -> ssize_t {
    0
}

extern "C" fn migration_write_data(
    _vfu_ctx: *mut vfu_ctx_t,
    _buf: *mut c_void,
    _count: u64,
    _offset: u64,
) -> ssize_t {
    0
}

extern "C" fn migration_data_written(_vfu_ctx: *mut vfu_ctx_t, _count: u64) -> c_int {
    0
}

fn serve_on_sock(path: &str, idx: usize) {
    let migr_size = unsafe { vfu_get_migr_register_area_size() } + 4096; // TODO: sysconf(_SZ_PAGE_SIZE);
    let mut migration_callbacks = vfu_migration_callbacks_t {
        version: VFU_MIGR_CALLBACKS_VERS as i32,
        transition: Some(migration_device_state_transition),
        get_pending_bytes: Some(migration_get_pending_bytes),
        prepare_data: Some(migration_prepare_data),
        read_data: Some(migration_read_data),
        write_data: Some(migration_write_data),
        data_written: Some(migration_data_written),
    };

    let socket_path = CString::new(path).unwrap();
    let vfu_ctx = unsafe {
        vfu_create_ctx(
            vfu_trans_t_VFU_TRANS_SOCK,
            socket_path.as_ptr(),
            0,
            &idx as *const usize as *mut usize as *mut _,
            vfu_dev_type_t_VFU_DEV_TYPE_PCI,
        )
    };

    if vfu_ctx.is_null() {
        println!("Init failed :< Socket already existing?");
        return;
    }

    GUEST_PCI_DEVICES[idx]
        .lock()
        .unwrap()
        .set_context(vfu_ctx as *mut std::ffi::c_void);

    let rc = unsafe {
        vfu_pci_init(
            vfu_ctx,
            vfu_pci_type_t_VFU_PCI_TYPE_CONVENTIONAL,
            PCI_HEADER_TYPE_NORMAL as i32,
            0,
        )
    };
    if rc < 0 {
        panic!("vfu_pci_init failed");
    }

    unsafe { vfu_pci_set_id(vfu_ctx, 0x1337, 0xCAFE, 0x0, 0x0) };

    let rc = unsafe {
        vfu_setup_region(
            vfu_ctx,
            VFU_PCI_DEV_BAR2_REGION_IDX as i32,
            0x1000,
            Some(bar2_access),
            VFU_REGION_FLAG_RW as i32,
            std::ptr::null_mut(),
            0,
            -1,
        )
    };
    if rc < 0 {
        println!("vfu_setup_region(bar2) failed :<");
        return;
    }

    let rc = unsafe {
        vfu_setup_region(
            vfu_ctx,
            VFU_PCI_DEV_MIGR_REGION_IDX as i32,
            migr_size,
            None,
            VFU_REGION_FLAG_RW as i32,
            std::ptr::null_mut(),
            0,
            -1,
        )
    };
    if rc < 0 {
        println!("vfu_setup_region(migr) failed :<");
        return;
    }

    let rc = unsafe {
        vfu_setup_device_migration_callbacks(
            vfu_ctx,
            &mut migration_callbacks as *mut _,
            vfu_get_migr_register_area_size(),
        )
    };
    if rc < 0 {
        println!("vfu_setup_device_migration_callbacks");
        return;
    }

    let rc = unsafe { vfu_setup_device_nr_irqs(vfu_ctx, vfu_dev_irq_type_VFU_DEV_INTX_IRQ, 1) };
    if rc < 0 {
        println!("vfu_setup_device_nr_irqs failed");
        return;
    }

    let rc = unsafe { vfu_setup_device_dma(vfu_ctx, Some(dma_register), Some(dma_unregister)) };
    if rc < 0 {
        println!("vfu_setup_device_dmna failed");
        return;
    }

    let rc = unsafe { vfu_realize_ctx(vfu_ctx) };
    if rc < 0 {
        println!("vfu_realize_ctx failed");
        return;
    }

    let rc = unsafe { vfu_attach_ctx(vfu_ctx) };
    if rc < 0 {
        println!("vfu_attach_ctx failed");
        return;
    }

    loop {
        let rc = unsafe { vfu_run_ctx(vfu_ctx) };
        if rc < 0 {
            let err = errno().0;
            if err == 107 /* not connected */ || err == 4
            /* EINTR */
            {
                break;
            }
            println!("vfu_run_ctx failed, rc = {}, errno = {}", rc, err);
            break;
        }
    }

    unsafe { vfu_destroy_ctx(vfu_ctx) };
}

fn main() {
    let h = std::thread::spawn(|| {
        let rc = std::panic::catch_unwind(|| {
            let mut emulator =
                Emulator::new(Box::new(DebugTerminal {}), (*GUEST_PCI_DEVICES).clone());

            let fs_contents = include_bytes!(env!("FS_IMG"));
            emulator.setup_filesystem(fs_contents.to_vec());

            let elf_contents = include_bytes!(env!("KERNEL_IMG"));
            emulator.setup_program(elf_contents.to_vec());

            // emulator.update_xlen(Xlen::Bit64);
            // emulator.enable_page_cache(true);
            emulator.run();
        });
        println!("Emulator result: {:?}", rc);
        std::process::Command::new("kill")
            .args(&["-9", "0"])
            .output()
            .ok();
        // unreachable
        std::process::exit(0);
    });

    let s1 = std::thread::spawn(|| {
        serve_on_sock("/tmp/device1.sock", 0);
        std::process::exit(0);
    });
    let s2 = std::thread::spawn(|| {
        serve_on_sock("/tmp/device2.sock", 1);
        std::process::exit(0);
    });

    s1.join().unwrap();
    s2.join().unwrap();
    h.join().unwrap();
}
