// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const probeText = `
BEGIN {
	printf("ready\n")
}

fentry:vmlinux:security_create_user_ns {
	signal(KILL);
}
	
fentry:vmlinux:security_file_open {
	$inode = args->file->f_inode;
	$d = $inode->i_sb->s_dev;
	$i = $inode->i_ino;

	if ($d == $1 && $i == $2) {
		signal(KILL);
	}
}
`

func getProbeParams(filename string) (uint64, uint64, error) {
	info, err := os.Stat("/flag.txt")
	if err != nil {
		return 0, 0, err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, fmt.Errorf("expected Stat_t, but was: %s", info.Sys())
	}

	return stat.Dev, stat.Ino, nil
}

func runTracer(ctx context.Context, dev, ino uint64, rdy chan struct{}, errs chan error) {
	cmd := exec.CommandContext(ctx, "/bin/bpftrace", "--unsafe", "-e", probeText, strconv.FormatUint(dev, 10), strconv.FormatUint(ino, 10))
	// cmd.Wait will close the reader automatically
	reader, err := cmd.StdoutPipe()
	if err != nil {
		errs <- err
		return
	}

	err = cmd.Start()
	if err != nil {
		errs <- err
		return
	}

	// wait for the probe to be ready
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "ready") {
			break
		}
	}

	close(rdy)
	err = cmd.Wait()
	if err != nil {
		panic(err)
	}
}

func mountFilesystems() error {
	if err := syscall.Mount("devtmpfs", "/dev", "devtmpfs", 0, ""); err != nil {
		return fmt.Errorf("error mounting /dev: %s", err)
	}

	if err := os.Mkdir("/proc", 0555); err != nil {
		return fmt.Errorf("error creating /proc: %s", err)
	}

	if err := syscall.Mount("proc", "/proc", "proc", 0, ""); err != nil {
		return fmt.Errorf("error mounting /proc: %s", err)
	}

	if err := os.Mkdir("/sys", 0555); err != nil {
		return fmt.Errorf("error creating /sys: %s", err)
	}

	if err := syscall.Mount("sysfs", "/sys", "sysfs", 0, ""); err != nil {
		return fmt.Errorf("error mounting /sys: %s", err)
	}

	if err := syscall.Mount("tracefs", "/sys/kernel/tracing", "tracefs", 0, ""); err != nil {
		return fmt.Errorf("error mounting /sys/kernel/tracing: %s", err)
	}

	if err := syscall.Mount("debugfs", "/sys/kernel/debug", "debugfs", 0, ""); err != nil {
		return fmt.Errorf("error mounting /sys/kernel/debug: %s", err)
	}

	if err := os.Mkdir("/tmp", 0555); err != nil {
		return fmt.Errorf("error creating /tmp: %s", err)
	}

	if err := syscall.Mount("tmpfs", "/tmp", "tmpfs", syscall.MS_NOEXEC|syscall.MS_NODEV|syscall.MS_NOSUID, ""); err != nil {
		return fmt.Errorf("error mounting /tmp: %s", err)
	}

	return nil
}

func shutdown() error {
	return syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
}

func spawnShell(ctx context.Context) error {
	withTimeout, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	cmd := exec.CommandContext(withTimeout, "/bin/sh")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: 99999, Gid: 99999},
		Setpgid:    true,
		Pdeathsig:  syscall.SIGKILL,
	}
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}

	if err := cmd.Wait(); err != nil {
		fmt.Println("command failed:", err)
	}
	return nil
}

func main() {
	if err := mountFilesystems(); err != nil {
		panic(err)
	}

	dev, ino, err := getProbeParams("/flag.txt")
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rdy := make(chan struct{})
	errs := make(chan error)
	go runTracer(ctx, dev, ino, rdy, errs)

	select {
	case err = <-errs:
		panic(err)
	case <-rdy:
	}

	if err := spawnShell(ctx); err != nil {
		panic(err)
	}

	if err := shutdown(); err != nil {
		panic(err)
	}
	panic("unreachable")
}
