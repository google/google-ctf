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
use std::env;
use std::process::Command;

fn main() {
    if let Ok(ref kernel_path) = env::var("KERNEL_SRC") {
        // Build kernel + file system
        Command::new("nix-shell")
            .args(&[
                "--command",
                "./make.sh",
                &*format!("{}/../cross-shell.nix", kernel_path),
            ])
            .current_dir(kernel_path)
            .status()
            .unwrap();

        println!("cargo:rustc-env=KERNEL_IMG={}/kernel/kernel", kernel_path);
        println!("cargo:rustc-env=FS_IMG={}/fs.img", kernel_path);

        // Kernel + userspace
        println!("cargo:rerun-if-changed={}", kernel_path);

        if let Ok(firmware_path) = env::var("FIRMWARE_SRC") {
            // Firmware
            println!("cargo:rerun-if-changed={}", firmware_path);
        }
    }
}
