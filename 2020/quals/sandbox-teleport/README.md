# Challenge Description

## Sandbox Teleport

Please write a full-chain exploit for Chrome. The flag is at /home/user/flag.
Maybe there's some way to tele<port> it out of there?

# Details (warning: spoilers)

This is a Chrome exploitation challenge in which you get
* MojoJS bindings
* RCE in the renderer
* A mojo interface in the browser for an arbitrary read

You'll have to exploit it by leaking port names in the browser process and turning that into an arbitrary file read.
An outline of how this works is described in https://googleprojectzero.blogspot.com/2020/02/escaping-chrome-sandbox-with-ridl.html.
You will need to leak the port name of a privileged URLLoaderFactory.

The example exploit is more complicated than needed:
* leak the binary base
* find the network context manager
* this gives you the router and the handle of the loader factory.
* you then look up this handle in a hash map from mojo to get the port
* this gives you the portname you want to leak
* now you need to patch a mojo interface in the renderer to use this port name
* create a urlloaderfactory use it 0x1337 times to get a known sequence number
* find the value in memory using the RCE handler and patch the port
* use the factory (which is no privileged) to upload the flag to your server

# Updating the chrome binary + exploit

* Just before the competition we should update the chrome binary to the latest stable version
* The supplied script should do that automatically for you (`update_chrome.sh`)
* Afterwards, you need to fix the exploit
 * Start `Xvfb :100 &`
 * Run the exploit `go run app.go`
 * Run chrome with a debugger attached, e.g. `rm -R /tmp/chrometmp 2>/dev/null; DISPLAY=:100 gdb -ex 'set follow-fork-mode parent' -ex run --args ./chrome --user-data-dir="/tmp/chrometmp" --enable-logging=stderr --enable-blink-features=MojoJS --disable-gpu 'http://localhost:1337/pwn.html'`
 * It should crash, but allow you to figure out all the offsets that need fixing:
  * Get the vtable ptr from the logs: "pwnVtable: 0x55c500d227a0"
  * Update the offset to the bin base in pwn.js
  * Update the kSystemNetworkContextManagerOff (addr via `p/x &'(anonymous namespace)::g_system_network_context_manager'`)
  * Update the kMojoCoreOff (addr via `x/a &'(anonymous namespace)::g_core'`)
 * If it now seems to endless loop after the "patching port" message, the start pointer for the heap addr is wrong
  * You need to update the offset on the stack for the heap ptr leak: `mov rcx, QWORD [rsp+0x20]`
  * Either try different values (0x10 worked before)
  * Or patch in an endless loop (`loop: jmp loop`) in the shellcode, attach with `gdb -p $pid` and check the stack for a valid heap ptr
