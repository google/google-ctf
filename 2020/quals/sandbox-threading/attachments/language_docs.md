# The DevMaster Sandboxed Programming Language
*Creating unintentional bugs since 2019™*

After our last disaster with a sandboxed build system, we've decided to pivot. We've created a sandboxed programming language with userland thread support. Why userland threads? Because they're fast! (Benchmark results pending.)

With this language, you can write code that's safe to run anywhere. Those executing your code can trust that it won't ever be able to read their precious `./flag` files.

(Legal notice: "can trust" may not be equivalent to "should trust." DevMaster Industries disclaims all liability resulting from running code written in the DevMaster Sandboxed Programming Language.)

## On the Subject of Greeting the World

The following is a complete example of Hello World written in the DevMaster Sandboxed Programming Language.

```
def int32 main() {
    print("Hello, World!\n");
    return 0;
}
```

```
def int32 main() {
```
This line is the start of a function definition. Function definitions begin with `def`, but otherwise behave like C. `int32` is the return type, and `main` is the name of the function. `()` indicates that the function takes no arguments. (`main` must always take no arguments.)

```
print("Hello, World!\n");
```
This is a call to the `print` function. `print` takes exactly one argument, of any type. `Hello, World!\n` is a string literal, meaning it has type `string`. This line is a statement, so it ends with a semicolon `;`.

```
return 0;
```
This function returns an `int32`, so it must have a `return` statement in all code paths. The value being returned is `0`. Numeric literals have type `uint64`, but can be implicitly cast to smaller types.

### Compiling and Running

The examples in this document are available in the examples directly. You can compile and run them as follows

```
./compile.sh examples/hello_world.simp examples/hello_world
./examples/hello_world
```

## A More In-Depth Example

This is an example concatenation function: it takes two strings, and returns a string that is the two strings concatenated together.

```
def string concatenate(string left, string right) {
  string s = make_string(size(left) + size(right));
  int32 i = 0;
  while (i < size(left)) {
    s[i] = left[i];
    i = i + 1;
  }
  int32 j = 0;
  while(j < size(right)) {
    s[i] = right[j];
    i = i + 1;
    j = j + 1;
  }
  return s;
}
```

```
def string concatenate(string left, string right) {
```

We are defining a function that returns a `string` called `concatenate` which takes two arguments, both of type `string`, called `left` and `right`.

```
string s = make_string(size(left) + size(right));
```

This line declares a new variable `s` of type `string`. `make_string` is a builtin function that takes an integer and returns a string of that length. (Contents not specified.) `size` is a builtin function that takes any type with "size" and returns the size of that type; in the case of strings, it returns the length of those strings. This line initializes `s` to be a string whose length is the sum of the lengths of `left` and `right`.

```
int32 i = 0;
int32 j = 0;
```

These are variable declarations and initializations. They work just like C.

```
while (i < size(left)) {
```

This is a while loop. It works just like C. The DevMaster Sandboxed Programming Language does not support `for` loops.

```
s[i] = left[i];
```

Using the `[]` operator on a `string` returns a `char`. The `[]` operator can appear on the left side of an assignment, just like C. This line copies the `i`th element from `left` into the `i`th position in `s`.

## On the Subject of Dynamic Memory

In order to ensure safety, it is not possible to obtain a reference to a variable on the stack, or a variable in an array. However, it *is* possible to dynamically allocate an object, in which case a reference to that object is returned. Here's an example of references and dynamic allocation:

```
def void increment(ref<int32> x) {
  deref(x) = deref(x) + 1;
}

def int32 main() {
  ref<int32> y = new<int32>(4);
  increment(y);
  print(deref(y));
  print("\n");
  
  return 0;
}
```

```
ref<int32> x
```
This declares `x` as a reference to an `int32`. `int32` is a *template argument* to `ref`.

```
deref(x) = deref(x) + 1;
```

The `deref()` function dereferences a `ref`, and is eqivalent to unary `*` in C. It is allowed to appear on the left side of an assignment. This line modifies the value pointed to by `x`, incrementing it by 1.

```
ref<int32> y = new<int32>(4);
```

This line allocates a new `int32`. `new` is a template function that takes a type as a template argument, allocates an object of that type on the heap, and returns a `ref` to it. `4` is an optional argument to `new`, used as the initializer for the new object.

Overall, this example prints `5 `.

It's also possible to print refs directly:

```
ref<int32> x = new<int32>(5);
print(x);
```

This will print details about the reference as well. For example:

```
ref<0x56340d49f480>(5)
```

## On the Subject of Arrays

Arrays can have their size specified at compile time or runtime.  These two variations look like this:

```
array<int32, 4> fixed_array;
array<int32> dynamic_array = make_array<int32>(4);
```

The first `array` is a compile-time array of size `4`. The second array is a dynamically sized array, whose size is also specified to be `4` as the argument to `make_array`. These two variations behave analagously to `std::array` and `std::vector` in C++ respectively: a fixed-size array on the stack will have its data members located on the stack, whereas a dynamic array will always have its data members located on the heap.

An uninitialized dynamic array has size `0`. 

Here's an example that creates a fixed-size array, copies it to a dynamic array, and prints it.

```
def int32 main() {
  array<int32, 4> arr;
  arr[0] = 0;
  arr[1] = 1;
  arr[2] = 2;
  arr[3] = 3;
  
  int32 i = 0;
  array<int32> dyn_arr = make_array<int32>(size(arr));
  while (i < size(arr)) {
    dyn_arr[i] = arr[i];
    i = i + 1;
  }
  
  print(dyn_arr);
  print("\n");
  return 0;
}
```

## On the Subject of Threads

Threads in this language behave much like `std::thread` in C++. Threads are created with `make_thread`, which takes a function as its first argument, and any parameters to pass to that function as subsequent arguments. `make_thread` returns a `thread` object, which represents a handle to the started thread. This handle allows you to `join` the thread if you so choose. Unlike `std::thread` or pthreads, there's no need to call `detach` if you don't want to join; that will happen automatically when all copies of the `thread` handle is destroyed.

Here's the hello world example, but printed from a thread.

```
def void t_func(string arg) {
  print(arg);
}

def int32 main() {
  string message = "Hello, World!\n";
  thread t = make_thread(t_func, message);
  join(t);
  return 0;
}
```

### On the Subject of Simultaneous Execution

By default, **only one of your threads will run at a time.** You can configure the number of threads capable of running simultaneously with the `set_max_native_threads(int64)` function. You may not call this function after any threads have been created. If the number of running threads ever exceeds the value that was passed to `set_max_native_threads`, preemption will be enabled, and your threads will be periodically swapped in and out.

## On the Subject of People Waving Flags

No threading library is complete without synchronization. The DevMaster Sandboxed Programming Language chose the `semaphore` as its synchronization primitive. With it, you can build any synchronization you want!

A `semaphore` is created as follows:

```
semaphore sem = 3;
```

Here, `3` is the initial value of the semaphore. The semaphore can be incremented by calling `up(semaphore)`, and decremented by calling `down(semaphore)`. A `semaphore` cannot be decremented below zero; a thread attempting to do so will block until another thread increments the semaphore.

Here's an example program that uses semaphores to synchronize two threads, ensuring that the numbers 1 through 10 are always printed in incrementing order:
```
semaphore sem1 = 1;
semaphore sem2 = 0;

def void t_func() {
  down(sem1);
  print(1);
  up(sem2);
  
  down(sem1);
  print(3);
  up(sem2);
  
  down(sem1);
  print(5);
  up(sem2);
  
  down(sem1);
  print(7);
  up(sem2);
  
  down(sem1);
  print(9);
  up(sem2);
}

def int32 main() {
  thread t = make_thread(t_func);
  
  down(sem2);
  print(2);
  up(sem1);
  
  down(sem2);
  print(4);
  up(sem1);
  
  down(sem2);
  print(6);
  up(sem1);
  
  down(sem2);
  print(8);
  up(sem1);
  
  down(sem2);
  print(10);
  up(sem1);
  
  print("\n");
  return 0;
}
```

A warning: you probably don't want to pass a `semaphore` by value, including to `make_thread`. This makes a *copy* of the semaphore. To share a semaphore between threads, you should use `new<semaphore>` and pass a `ref` to the semaphore, or make the semaphore a global. Note that the builtins `up()` and `down()` are by their nature special: no copy is made when passing a semaphore to these functions.

# On the Subject of Variable Lifetimes

Variable lifetimes behave like they do in C++. An object on the stack is destroyed when the enclosing scope exits (e.g. the function returns). Objects in arrays are destroyed when the array is destroyed.

`ref`s use reference-counting. A referred-to object is destroyed when the last reference to it is destroyed.

# On the Subject of Types

The following types are available:
 * `void`: Only valid as the return type of a function. Indicates that the function does not return a value.
 * `char`: a one-byte unsigned integer.
 * `int32`: a 4-byte signed integer.
 * `uint32`: a 4-byte unsigned integer.
 * `int64`: an 8-byte signed integer.
 * `uint64`: an 8-byte unsigned integer.
 * `ref<type>`: A reference to an object of type `type`. References can refer to any type except `void`, including arrays and other references. References use reference counting to destroy objects when all references to the object are destroyed. References can be null, and are null when uninitialized.
 * `array<type, size>`: a fixed-size array holding `size` elements of type `type`. Can hold any type except `void`, including other arrays and references.
 * `array<type>`: a dynamically-sized array holding elements of type `type`. Can hold any type except `void`, including other arrays and references.
 * `string`: An alias for `array<char>`. 
 * `func<return_type, arg_types...>`: A function that returns `return_type` and takes arguments of types `arg_types...`. 
 * `thread`: A handle to a thread. Copies still refer to the same thread.
 * `semaphore`: A thread-safe integer that can be incremented and decremented, but can never go below zero. While a semaphore is abstractly an integer, it is not an "integral type".

# On the Subject of Builtins

The following basic builtins are available:

 * `make_array<type>(integral)`: Returns an `array<type>` of size `integral`.
 *  `make_string(integral)`: An alias for `make_array<char>(integral)`.
 *  `size(array)`: Returns the size of the provided array. Array can be of fixed or dynamic size.
 *  `new<type>()`, `new<type>(initializer)`: Allocate an object of type `type` on the heap, and return a reference to it. If an initializer is passed in, that value is used to initialize the object, as though you had written `type x = initializer`.
 *  `deref(ref)`: Dereferences the provided reference. This function is special in that it can appear on the left-hand side of an assignment.
 *  `print(object)`: Print the provided object of any type.
 *  `read(integral)`: Read `integral` bytes from stdin, and return a string. If EOF is reached, returns a shorter string containing the available bytes.
 *  `up(semaphore)`, `down(semaphore)`: Increment or decrement the provided semaphore.
 *  `join(thread)`: Block until the thread referred to by the provided handle has finished executing. Does nothing if the thread is already finished or if the thread handle is uninitialized.
 *  `make_thread(func, params...)`: Create a new thread. The thread will execute `func` with params `params...` when starting. Returns a `thread` handle that can be passed to `join()`.
 *  `set_max_native_threads(integral)`: Sets the maximum number of threads that can be executed simultaneously. Defaults to 1. This cannot be called if any threads have already been created.
 *  `usleep`: Sleep for at least the provided number of microseconds. The current thread does not yield the CPU.

The following conversion functions are available:

 *  `hex_to_bytes(string)`: Converts a hex string to a byte string.
 *  `bytes_to_hex(string)`: Converts a byte string to a hex string.
 *  `hex8(string)`: Converts a hex string of length 2 to a char.
 *  `hex32(string)`: Converts a hex string of length 8 to a uint32.
 *  `hex64(string)`: Converts a hex string of length 16 to a uint64.
 *  `to_hex(integral)`: Converts the specified integral to a hex string.
 *  `bytes8(string)`: Converts a byte string of length 1 to a char.
 *  `bytes32(string)`: Converts a byte string of length 4 to a uint32.
 *  `bytes64(string)`: Converts a byte string of length 8 to a uint64.
 *  `to_bytes(integral)`: Converts the specified integral to a byte string.
 *  `hex_to_byte(char major, char minor)`: Returns the byte corresponding to the provided hex value. `major` refers to the 16s-place, and `minor` refers to the 1s-place.
