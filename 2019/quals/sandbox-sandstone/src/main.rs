/*
Copyright 2019 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

extern crate libc;
extern crate tempfile;

static CARGO_TOML_TEMPLATE: &str = r#"
[package]
name = "sandstone"
version = "0.1.0"
edition = "2018"

[dependencies]
libc = "0.2.51"
seccomp-sys = "0.1.2"
"#;

static MAIN_TEMPLATE: &str = r#"
#![feature(nll)]
extern crate libc;
extern crate seccomp_sys;

use seccomp_sys::*;

mod sandstone;

fn setup() {
    unsafe {
        let context = seccomp_init(SCMP_ACT_KILL);
        assert!(!context.is_null());
        assert!(seccomp_rule_add(context,
                         SCMP_ACT_ALLOW,
                         libc::SYS_write as i32,
                         1,
                         scmp_arg_cmp {
                            arg: 0,
                            op: scmp_compare::SCMP_CMP_EQ,
                            datum_a: 1,
                            datum_b: 0
                         }) == 0);
        assert!(seccomp_rule_add(context,
                         SCMP_ACT_ALLOW,
                         libc::SYS_sigaltstack as i32,
                         0) == 0);
        assert!(seccomp_rule_add(context,
                         SCMP_ACT_ALLOW,
                         libc::SYS_mmap as i32,
                         0) == 0);
        assert!(seccomp_rule_add(context,
                         SCMP_ACT_ALLOW,
                         libc::SYS_munmap as i32,
                         0) == 0);
        assert!(seccomp_rule_add(context,
                         SCMP_ACT_ALLOW,
                         libc::SYS_exit_group as i32,
                         0) == 0);
        assert!(seccomp_rule_add(context,
                         SCMP_ACT_TRACE(0x1337),
                         0x1337,
                         0) == 0);
        assert!(seccomp_load(context) == 0);
    }
}

fn main() {
    setup();

    sandstone::main();
}
"#;

static SANDSTONE_TEMPLATE: &str = r#"
#![feature(nll)]
#![forbid(unsafe_code)]

pub fn main() {
    println!("{:?}", (REPLACE_ME));
}
"#;

fn write_file(dir: &tempfile::TempDir, name: &str, contents: &str) {
    let path = dir.path().join(name);
    std::fs::create_dir_all(path.as_path().parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

fn build(dir: &tempfile::TempDir) {
    let mut cmd = std::process::Command::new("cargo");
    cmd.arg("build").arg("--release")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .current_dir(dir.path());

    if let Ok(args) = std::env::var("CARGO_EXTRA_ARGS") {
        for arg in args.split(" ") {
            cmd.arg(arg);
        }
    }

    cmd.status().unwrap();
}

fn child(dir: &tempfile::TempDir) {
    use std::ffi::CString;

    unsafe {
        assert!(libc::raise(libc::SIGSTOP) != -1);
        let executable = dir.path().join("target/release/sandstone");
        let cmd = CString::new(executable.as_os_str().to_str().unwrap()).unwrap();
        let argv = vec![cmd.as_ptr(), std::ptr::null()];
        libc::execvp(cmd.as_ptr(), argv.as_ptr());
    }
    panic!("execvp failed");
}

fn print_flag() {
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    let mut f = std::fs::File::open("flag").unwrap();
    std::io::copy(&mut f, &mut handle).unwrap();
}

fn parent(child: libc::pid_t) {
    use libc::*;

    assert!(unsafe {
        ptrace(
            PTRACE_SEIZE,
            child,
            0,
            PTRACE_O_TRACESECCOMP | PTRACE_O_EXITKILL,
        )
    } != -1);

    loop {
        let mut status: c_int = 0;
        let pid = unsafe { wait(&mut status) };
        assert!(pid != -1);

        if unsafe { WIFEXITED(status) } {
            break;
        }

        if (status >> 8) == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8)) {
            let mut nr: c_ulong = 0;
            assert!(unsafe {
                ptrace(PTRACE_GETEVENTMSG, pid, 0, &mut nr)
            } != -1);

            if nr == 0x1337 {
                assert!(unsafe {
                    ptrace(PTRACE_KILL, pid, 0, 0)
                } != -1);
                print_flag();
                break;
            }
        }

        unsafe { ptrace(PTRACE_CONT, pid, 0, 0) };
    }
}

fn run(dir: &tempfile::TempDir) {
    unsafe { libc::alarm(15) };

    let pid = unsafe { libc::fork() };
    match pid {
        0 => child(&dir),
        _ if pid < 0 => panic!("fork failed"),
        _ => parent(pid),
    };
}

fn read_code() -> String {
    use std::io::BufRead;

    let stdin = std::io::stdin();
    let handle = stdin.lock();

    let code = handle
        .lines()
        .map(|l| l.expect("Error reading code."))
        .take_while(|l| l != "EOF")
        .collect::<Vec<String>>()
        .join("\n");

    for c in code.replace("print!", "").replace("println!", "").chars() {
        if c == '!' || c == '#' || !c.is_ascii() {
            panic!("invalid character");
        }
    }

    for needle in &["libc", "unsafe"] {
        if code.to_lowercase().contains(needle) {
            panic!("no {} for ya!", needle);
        }
    }

    code
}

fn main() {
    println!("{}", "Reading source until EOF...");
    let code = read_code();

    let temp = tempfile::tempdir().unwrap();
    write_file(&temp, "Cargo.toml", CARGO_TOML_TEMPLATE);
    write_file(&temp, "src/main.rs", MAIN_TEMPLATE);
    write_file(&temp, "src/sandstone.rs", &SANDSTONE_TEMPLATE.replace("REPLACE_ME", &code));
    build(&temp);
    run(&temp);
}
