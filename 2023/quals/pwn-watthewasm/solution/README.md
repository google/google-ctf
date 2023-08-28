# Google CTF 2023 - pwn: Wat the WASM writeup

```
Can you exploit v8 without JavaScript?
```

As the name says, watthewasm is a Wasm exploitation challenge. You get a patch that re-introduced a bug in v8's liftoff compiler and have to exploit it by providing a Wasm module in wat format.

Here's the patch:

```patch
diff --git a/src/wasm/baseline/liftoff-compiler.cc b/src/wasm/baseline/liftoff-compiler.cc
index 7d8bcc6adf..f687ca85af 100644
--- a/src/wasm/baseline/liftoff-compiler.cc
+++ b/src/wasm/baseline/liftoff-compiler.cc
@@ -42,6 +42,9 @@ constexpr auto kStack = LiftoffAssembler::VarState::kStack;

 namespace {

+static void print_flag() __attribute__((used, retain));
+void print_flag() { (void)system("cat /flag"); }
+
 #define __ asm_.

 // It's important that we don't modify the LiftoffAssembler's cache state
@@ -781,20 +784,14 @@ class LiftoffCompiler {
     const int kMax = v8_flags.wasm_tiering_budget / 4;
     if (budget_used > kMax) budget_used = kMax;

-    LiftoffRegister budget_reg(tmp2);
+    LiftoffRegList pinned(tmp1, tmp2);
+    LiftoffRegister budget_reg =
+        pinned.set(__ GetUnusedRegister(kGpReg, pinned));
+
     // Be careful not to cause caching of the instance.
-    Register instance = __ cache_state()->cached_instance;
-    if (instance == no_reg) {
-      instance = tmp1;
-      __ LoadInstanceFromFrame(instance);
-    }
-    constexpr int kArraySize = kSystemPointerSize;
-    constexpr int kArrayOffset =
-        WASM_INSTANCE_OBJECT_FIELD_OFFSET(TieringBudgetArray);
-    static_assert(WASM_INSTANCE_OBJECT_FIELD_SIZE(TieringBudgetArray) ==
-                  kArraySize);
     Register array_reg = tmp1;  // Overwriting {instance}.
-    __ LoadFromInstance(array_reg, instance, kArrayOffset, kArraySize);
+    LOAD_INSTANCE_FIELD(array_reg, TieringBudgetArray, kSystemPointerSize,
+                        pinned);
     uint32_t offset =
         kInt32Size * declared_function_index(env_->module, func_index_);
 #if V8_TARGET_ARCH_ARM || V8_TARGET_ARCH_ARM64
```

We can see that after the patch, we're creating new temporary registers and directly load a field from the Wasm instance even though there's a comment warning us not to do this.

For some extra information, we can check out the code in [chromium's codesearch](https://source.chromium.org/chromium/chromium/src/+/main:v8/src/wasm/baseline/liftoff-compiler.cc;l=730;drc=4c4057566cb5d049b49868bb6f6dea5fff709a64). Using its blame feature, this leads us to [crbug.com/1339321](https://crbug.com/1339321) which has a bit more background about what the bug was.

```
We had two CF issues before that br_if (crbug.com/1314184) and br_table (crbug.com/1338075) change the cache_state() on a path that only gets conditionally executed. As a result, the cache_state is wrong if that path didn't get executed.
```

Ok, looks like we're modifying the cache state in a place where we shouldn't. Why is that a problem?

## Liftoff

As mentioned before, Liftoff is one of the Wasm compilers in v8. In particular, it's the baseline compiler that gets executed the first time you instantiate a module and run a function inside. So what's the CacheState in Liftoff?

Wasm is a stack-based machine. Check out this example in wat format:
```
i32.const 0x1300
i32.const 0x37
i32.add
```

It first pushes two constants onto the value stack and the `i32.add` instruction will pop two values add them and push the result back.

In the Liftoff compiler, we translate this to x64 machine code and we obviously want to use the CPU registers to store these values. That means we need to keep track which Wasm value is mapped to which CPU register. And since we have a limited number of registers, we also need to spill the values to the machine stack from time to time. This is what's being tracked in the CacheState object.

Now, whenever we do a control-flow transfer like executing a conditional branch or jumping back in a loop, we need to ensure that the cache state fits to what the CPU sees afterwards. As the compiler, we can for example insert instructions that load all the right values into the registers or spill them to the stack.

The bug in our case is that we're under a conditional branch: the instructions that we're emitting might not get executed. That means, we either need to restore the register/stack state to what it was before or, what the code before that patch was doing, be very careful not to change the cache state. After the patch however, we acquire temporary registers (which can spill other registers) and load the instance pointer to a register. The CacheState gets automatically updated to include these changes, but: we might never execute this code so the CacheState will be wrong!

## Exploitation

We can turn this behavior into an info leak easily:
```
  (loop $my_loop
    i32.const 0
    br_if $my_loop
  )
```
The `br_if` instruction includes the code from our patch, it's part of the TierupCheck, so a check if we should switch to a version of this code that was optimized more heavily.
This TierupCheck is only executed if the branch is taken. Since we're not taking it, we'll never acquire the temporary registers which might spill an existing register to the stack. However, even if we didn't execute the code, the CacheState was updated by the compiler to say that another register has been spilled. Now reading the associated value will read uninitialized memory from the machine stack.

Now for memory corruption we can use the second part of the patch, the cached instance register.
Similarly to before, the `br_if` will update the CacheState to say that we cached the Wasm instance (a v8 internal object) in a register, but this never happens!
Now, if we compile more code that needs to access the Wasm instance, it will use an uninitialized register which can have a value that we control.

Through different code paths, you can turn this either into arbitrary memory read/write or direct pc control. I added a `print_flag()` function to the patch for convenience. You just need to set up the machine stack with some controlled values (spilled registers), trigger the bug to point the cached instance to a controlled register and finally use `call_indirect` which will use your fake Wasm instance to give you `pc` control.
