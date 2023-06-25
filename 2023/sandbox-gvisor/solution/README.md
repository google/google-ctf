# Writeup for gVisor

## Challenge description

In this challenge, we are given a gVisor `runsc` binary that executes an arbitrary program in a sandbox. The gVisor binary contains a new syscall 666 to read the flag, however it is only added to the ARM64 syscall table. We cannot use the ARM64 syscall, because we run the AMD64 version. So, how do we invoke the `GetFlag` syscall? The gVisor challenge also has some bugs introduced. Namely, both functions `restoreFPState` and `saveFPState` do a copy on an unsafe slice with the offset `FPState` that is provided by the application via shared memory (the `sysmsg`), hence untrusted. This results in out-of-bounds R/W access, and can allow an attacker to compromise the Sentry process. In our case, this memory corruption vulnerability provides us a way to invoke the `GetFlag` syscall.

## Intended solution

As hinted in the challenge, there is the `GetFlag` syscall which is of our interest. In order to execute it, we have to corrupt the syscall table and for instance replace a function pointer of a syscall with the address of `GetFlag`. After that, the flag can be retrieved with `syscall(SYS_any_number, flag)`.

To achieve that, we need to turn our out-of-bounds R/W primitives into arbitrary R/W primitives - which can be easily achieved by finding out the base address. For that, the challenge already provides a free information leak. Namely, the `sysmsg` struct contains the field `sentry_addr` that holds the pointer to the `sysmsg` struct in Sentry address space.

Since gVisor is not compiled with PIE, its base address is always at `0x00400000`, therefore ASLR does not need to be defeated.

Finally, we need to figure out how to trigger the out-of-bounds R/W vulnerabilities. Looking at the code, we can find many instances where `saveFPState` is invoked through `PullFullState`. For instance, when a child process is ptraced.

The FP state is saved in this struct:

```
type State struct {
	// The system registers.
	Regs Registers

	// Our floating point state.
	fpState fpu.State `state:"wait"`
}
```

which can be fetched for example at:

```
func (s *State) PtraceGetRegSet(regset uintptr, dst io.Writer, maxlen int, fs cpuid.FeatureSet) (int, error) {
	switch regset {
	case _NT_PRSTATUS:
		if maxlen < ptraceRegistersSize {
			return 0, linuxerr.EFAULT
		}
		return s.PtraceGetRegs(dst)
	case _NT_PRFPREG:
		return s.fpState.PtraceGetFPRegs(dst, maxlen)
	case _NT_X86_XSTATE:
		return s.fpState.PtraceGetXstateRegs(dst, maxlen, fs)
	default:
		return 0, linuxerr.EINVAL
	}
}
```

So, all it takes to leak the out-of-bounds data is to ptrace the child process, and make the child process trigger a signal with a malicious `fpstate` in sysmsg. After catching the signal in the parent process, we can simply call `ptrace(PTRACE_GETREGSET, pid, NT_X86_XSTATE, &iov)` to fetch the data.

Since the syscall stub sets the `fpstate` to a constant address, we use a separate thread and perform a race condition to change the value:

```
void *race(void *arg) {
  while (1) {
    sysmsg->fpstate = malicious_fpstate;
  }
  return NULL;
}
```

Based on the content of the leak, we can deduce whether the race was successful or not, and if not then we repeat the leak.

We use this primitive to leak the syscall table (max. 0xa80 bytes). Our strategy is to modify the content of the syscall table, i.e. redirect a pointer, and then write back the syscall table.

Looking at the code, we can see that `restoreFPState` is invoked in `switchToApp` when switching back to the application after a signal. Also, we can see that on `SignalRestore`, the content of `c.fpState` is overwritten with the content provided by the application (which is fully controllable):

```
		fpState := c.fpState.Slice()
		if _, err := st.IO.CopyIn(context.Background(), hostarch.Addr(uc.MContext.Fpstate), fpState, usermem.IOOpts{}); err != nil {
			c.fpState.Reset()
			return 0, linux.SignalStack{}, err
		}
		c.fpState.SanitizeUser(featureSet)
```

Thus, we install a signal handler with e.g. `signal(SIGUSR2, (void *)sighandler)`, and in the signal handler we modify the FP registers like `memcpy(ucontext->uc_mcontext.fpregs, arbitrary_content, 0xa80);`. With the same race thread, on sigreturn, we overwrite memory content with an offset provided by the application. Again, with an offset to the syscall table. After the signal returns, we can invoke `syscall(SYS_any_number, flag)`, and if it returns 0x1337, then the syscall function pointer has been redirected successfully and the `flag` buffer contains the flag. Otherwise, we repeat the procedure.
