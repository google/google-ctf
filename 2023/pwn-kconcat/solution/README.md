# Google CTF 2023 - pwn: kconcat writeup

## Challenge

### Scoreboard description

```
As we are running our mitigated kernel (https://github.com/thejh/linux/blob/b97cbfe06757d908412e6afa217b1fe77dc48282/MITIGATION_README),
we could safely implement a super fast text concatenation functionality directly in the kernel.

Get root code exec and run `cat /flag`. (Note: the flag file is 3780 bytes long.)
```

### The kernel module

The challenge implements a custom kernel module, which has the following functionality:

* exposes `/dev/kconcat` device which a concatenation service: it can concatenate multiple text segments and read the concatenated text

* when you open the device, you can write text segments (via `write` syscall) into the device or use a predefined templates (via `ioctl 0x1234`) which are stored under the `/etc/kconcat/message-templates/` directory

* there is an additional moderation feature (`ioctl 0x1337`) which deletes all segments (even from other devices) containing a specified "blocked" word, but this functionality only available with `CAP_SYS_ADMIN`

The segments are stored in the following structure:

```c
#define MAX_MESSAGE_SIZE 512

struct concat_segment {
	int is_file;
	char message_or_filename[MAX_MESSAGE_SIZE];
};
```

The `is_file` field specifies whether the `message_or_filename` field contains the full path of the template file (under `/etc/kconcat/message-templates/`) or the message itself.

To support the moderation feature, all open devices are stored in a linked list and this list is prepared for multi-threaded operation, uses mutex to only allow one thread to work on the structure:

```c
#define MAX_SEGMENT 10

static struct mutex global_mutex;
static struct list_head fds;

struct fd_info {
	struct list_head list;
	struct mutex lock;
	int is_admin;
	int segment_count;
	struct concat_segment *segments[MAX_SEGMENT];
};
```

### Kernel version

The challenge uses a customized kernel version which is based on the LTS 6.1.32 version, but adds our custom mitigation which tries to prevent the following exploitation techniques (as mentioned on [our blog post](https://security.googleblog.com/2022/08/making-linux-kernel-exploit-cooking.html) where the mitigation was introduced):

  * Cross-cache attacks
  * Elastic objects
  * Freelist corruption
  * Out-of-bounds write on slab (from one slab to another, prevented by guard pages)

## Vulnerabilities

There are two (intentional) vulnerabilities in the service:

1. When the `ioctl` is called and the process has `CAP_SYS_ADMIN` capability then the device is put into "administration" mode and further calls to the device also became privileged. 
   
   This is a problem, as you can pass an FD to a setuid binary and it may call `ioctl` on it, putting the FD into "admin" mode, and then the unprivileged process can also execute privileged functionality (in this case the `moderation` function).

   The inspiration for this vulnerability was [CVE-2023-2002: Linux Bluetooth: Unauthorized management command execution](https://www.openwall.com/lists/oss-security/2023/04/16/3).

2. The moderation feature although locks the admin FD, contrary to other functionalities can modify other FD's segments and does not use the mutex for this access. 

   This bug can be used to create a "race condition" between the `read` operation to read a template file and the `moderation` operation which deletes that template structure, causing a UAF. 
   
   The race is seemingly tight, as the `moderation` unlinks the template (`info->segments[i] = 0`) before deleting it (`kfree(segment)`), and the `read` operation skips deleted segments, so we will need an extra trick to make the exploit reliably win the race.

Additionally the module does something risky it shouldn't: reading files. [Driving Me Nuts - Things You Never Should Do in the Kernel](https://www.linuxjournal.com/article/8110) explains this in more detail.

## Exploitation

The exploit (attached as [exp.c](exp.c)) does the following:

1. Creates a device used for moderation (`admin_fd`), executes the `/usr/bin/mount` setuid binary using `admin_fd` as `stdout`. This will trigger a `TCGETS ioctl` call (to get terminal properties), but it also puts the `admin_fd` into admin mode, thus enable calling `moderation` on that FD.

2. Relaunches itself in a new user namespace where it has extra privileges

3. Mounts `/etc/kconcat/message-templates` as `tmpfs`, so we have full control over the templates directory, which we would not able to modify outside the namespace.

4. Creates a new template (called `deletethis`) as a FIFO, which enables us to block the read operation executed by the kernel, so we can stop the kernel just at the right point: when the segment was not deleted yet, and the read operation is in progress, and at this point we can delete the segment causing UAF and overwriting the memory of a newly allocated structure with the file's content which we control due to that we control the pipe.

5. Leaks kernel text address to bypass KASLR by the method described above:

   * Creates a device

   * Adds a template segment (`deletethis`) which points to a blocked FIFO pipe

   * Starts reading in a new thread which blocks the kernel when it tries to read the template file (backed by our pipe)

   * Calls `moderation` function via `admin_fd` to delete segments containing `deletethis` (this also triggers if the filename contains the blocked word) and frees the `struct concat_segment` of our template segment

   * Creates a `struct tty_struct` in the memory space used by `struct concat_segment` previously (both are allocated from the `kmalloc-1k` cache)

   * Writes 0x14 `AAAA`...s into the pipe, which unblocks the kernel read operation and overwrites the `tty_struct` from offset 0x4 (`message_or_filename` field) with the 0x14 `AAAA`...s as the next `tty_struct` field at offset 0x18 is the `struct tty_operations *ops` which contains the value of `ptm_unix98_ops`, which is a global variable, thus leaking a kernel address

   * Waits for the read thread to return and get the 8-byte leak (kernel pointer) from the buffer

6. Creates a fake `struct tty_operations` with the same method as above, just writes the struct content instead of `AAAA`...s, the only field set is `tty_operations.ioctl` which is set to the address of the ROP gadget of `mov dword ptr [rdx], ecx` which used via ioctl is an 4-byte write-what-where gadget as we can control both `rdx` and `ecx` via calling `ioctl`. This also leaks the value of `tty_operations` at offset 0xf8 which contains its own address, so we can calculate the `tty_struct`'s address easily too. (The field `struct mutex winsize_mutex` -> `struct list_head wait_list` -> `struct list_head *next` points to itself as there are no other elements in the list.)

7. Overwrites a `tty_struct` with an other, fake `struct tty_struct` and sets its `struct tty_operations *ops` field to our previously allocated fake `tty_operations`, thus achieving code executing by controlling the `ioctl` call.

8. Overwrites `core_pattern` with `|/bin/chmod 666 /flag core\0` (via our 4-byte ARW ioctl in multiple steps).

9. Launches a new process which crashes itself by calling `*(int*)0 = 0`, triggering the overwritten core dump handler, making `/flag` readable for everyone.

10. Cats the flag.

### Notes on the exploitation

1. As mentioned in the beginning, the challenge uses a custom kernel with extra mitigations added. In this case the mitigation did not protect us to exploit the vulnerability as the vulnerability primitive was too strong and it allowed us the easily find a (well-known) structure (`tty_struct`) in `kmalloc-1k` which could be freely overwritten.

   This weakness of the mitigation is known and documented in the mitigation's [README](https://github.com/thejh/linux/blob/b97cbfe06757d908412e6afa217b1fe77dc48282/MITIGATION_README#L50), but we expect real kernel vulnerabilities harder to be exploited. We'd like collect some statistics in this area and you can also help by proving us wrong and joining our [kernelCTF program](https://google.github.io/security-research/kernelctf/rules) where we pay up to $133k for exploiting Linux kernel vulnerabilities (the mitigation bypass bonus is $20k).

2. The flag is deliberately longer than 512 bytes, so you cannot overwrite the template filename via the UAF and then use the FD `setuid` trick to read `/flag` by a privileged process (this was an unintended solution found by an internal test run tester).

## The flag

```
                                 :!J5PGBB##BBGPJ!:                              
                              .?PB###############BP!                            
                             7B&###################&P^                          
                            J&#######################B~                         
                           !##########################B.                        
                           P##############&##&########&J                        
                          :B##B55G#######57~~75########G                        
                          :##Y.   !B###B^      ^G#######:                       
                          :#B. ?Y^ 7&#&!  JBB?  !#######~                       
                          .BB ^&&G:!GGG7^7&&&B. ^#######~                       
                           G&J.PBJ~7: .!~!YG#Y..5#######~                       
                           P&#?~.  .   .    .^~?B#######~                       
                           GG^~             :~: ~#######!                       
                          ^#B7~~^:.    ..^^~^..^J#######P                       
                          5###7!!~^^^^^^:::^~!!~.Y&######Y                      
                         ?###P  ^!!^:::^~!!^..   .B######&5.                    
                        J###&!    .:^^^^:         ~#######&B!                   
                      ^P&##&5                      ?&########5^                 
                    .J#####B:                       Y&#########J.               
                   !B&#####~                         5&##G#####&B7              
                 :5#&BB###!                          .5&#GYP######5:            
                ~B&#GYB##7                            .5&##PJB####&B~           
               ?###PJ###7                               Y&##G7G######7          
              J&##5?###7                                 J&##B~G######?         
             Y&##G!###?                                   5&#&Y^#######!        
            ?&###~5&#5                                    .G##B.5######B:       
           ~####P.B#B:                                     !&&B ?&#####&J       
           P####5 P&J                                       J57 J&######G       
          ^#####B.^#~                                     :?JJ?!7?YG####B.      
          ~#####&5 ^.                                    ^B&&&&&#G5?7P##G       
          !#G55PB&G!.                                  7Y5#########&B~B&7       
        .JP~    .7G&GJ~.                              55..B&######&#PY5GY~      
     .^7P?.       .Y&&#BY~.                          7G   ^5B###BP?^    ^PY     
  !JJJ?!.           ?###&#G?.                        G?     :^~^.        .B7    
.PY^.                !#####&G!                      .B~                   7B.   
?B                    ~B&#####!                     ^#:                    JP~  
~B:                    .Y####B!                     7G.                     ~PJ.
.B7                      ~PG!.                     .B7                        P5
^B~                        7P!                   .~5P                       .~PJ
PY                          :PGJ!:.         .^!?5B##^                   .^7JYJ^ 
#?                           .B&##BP55YY55PGB##&###5                 ^7YY?!:    
~5J7!~^^::..                  P&&&&&###BBBB#######&?              .75Y!:        
  :~!77??JJJJJ?~:           .JGJ?7!~^:.....::^~~!!YG:           .7PJ:           
            .:~7JJJ?!~~^^~!?Y?.                    7P7:     .:!J5?:             
                 .:~!77??7!^.                       :7YYYJJYYJ7^                

CTF{C0ngr4ts_0n_pwn1ng_th3_k3rn3l!_Pwn_k3rn3lCTF_t00_4nd_g3t_$133k_f0r_1t_https://google.github.io/security-research/kernelctf/rules}
```