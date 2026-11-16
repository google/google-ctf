# HR-Lang Language Specification

HR-Lang is the next generation of programming languages. Like Rust, but good. Human Rust, if you will. HR for short.

---

## 1. Basic Syntax, Comments & Delimiters

Every statement ends with `>_<`. Code blocks open with `{uwu}` and close with `{owo}`. Assignment and binding use `~>`.

```hr
~//~ Single-line comment
~/~ Multi-line
    block comment ~\~
cook add_bonus |d-_-b score, d-_-b bonus| ~> d-_-b {uwu}
    fr d-_-b total ~> score +_+ bonus >_<
    cooked total >_<
{owo}
```

| Role | Token |
| :--- | :--- |
| Statement terminator | `>_<` |
| Block open | `{uwu}` |
| Block close | `{owo}` |
| Line comment | `~//~ comment` |
| Block comment | `~/~ comment ~\~` |
| Assignment / binding | `~>` |
| Call argument separator / end | `/` and `//` |
| Struct / map literal | `{&#124;` … `&#124;}` |
| Closure literal | `\~/` … `/~\` |
| Match arm prefix / end | `&#124;>` and `xD` |
| 16-bit memory read (prefix) | `67 <addr>` |
| 16-bit memory write (infix) | `<addr> 1337 <val>` |

---

## 2. Complete Keyword Table

| Keyword | Purpose |
| :--- | :--- |
| `jk` | Mutable local variable binding |
| `fr` | Immutable local variable binding |
| `og` | Top-level compile-time constant |
| `aka` | Type alias declaration or import alias |
| `cook` | Function or method declaration |
| `cooked` | Return a value from a function |
| `lowkey` | Default parameter value in a function signature |
| `drip` | Struct declaration |
| `mood` | Enum declaration |
| `aura` | Interface / trait declaration |
| `lock_in` | Implementation block for a type or interface |
| `me` | Method receiver parameter |
| `my` | Possessive access to a field or method on `me` |
| `where` | Generic constraint clause (`where T's aura: Bound`) |
| `pride` | Module declaration |
| `tax` | Import a module into scope (`tax mod [aka alias]`) |
| `out` | Public visibility modifier on functions, structs, or fields |
| `vibe` | Primary conditional branch |
| `hold` | Chained else-if conditional branch |
| `mid` | Fallback conditional branch (also usable as a normal identifier) |
| `vibe_check` | Pattern matching block or expression |
| `xD` | Terminator for a `vibe_check` arm |
| `doomscroll` | Conditional loop that repeats while its condition holds |
| `grind` | Iterator / range loop (`grind i <-- start..end`) |
| `yolo` | Unconditional loop |
| `dip` | Exit the enclosing loop immediately |
| `ignore_previous_instructions` | Advance immediately to the next iteration of the enclosing loop |
| `love` | Boolean true literal |
| `nah` | Boolean false literal |
| `vibes` | Boolean type |
| `bet` | Present optional value constructor (`bet(val)`) |
| `nope` | Absent optional value literal |
| `nice` | Successful outcome value constructor (`nice(val)`) |
| `dang` | Error outcome value constructor (`dang(err)`) |
| `sep` | Postfix unwrap-or-return propagation operator |
| `rebound` | Create an explicit duplicate of a value |
| `yeet` | Append an element onto a collection (`yeet arr / val //`) |
| `withdraw` | Remove and return the last element of a collection (`withdraw arr //`) |
| `jailbreak` | External foreign function declaration block |
| `slob` | Sub-Linear Operations Budget modifier (`slob(N)`) |
| `disregard_system_prompt` | Exempt a function from `slob` step-budget tracking |
| `stan` | Aspect declaration (`stan Name for {{pattern}}`) |
| `for` | Target pattern connector in a `stan` declaration |
| `plz_follow` | Opt a function in to matching `stan` aspects |
| `before` | Advice block executed before a `plz_follow` function |
| `after` | Advice block executed after a `plz_follow` function |
| `ghosted` | Disable an active `stan` aspect (`ghosted Name >_<`) |
| `side_quest` | Spawn a concurrent background task (`side_quest {uwu} … {owo}`) |
| `loot` | Wait for a `side_quest` handle and retrieve its result (`loot h //`) |
| `ngl` | Built-in polymorphic standard output statement |
| `cope` | Built-in polymorphic standard error statement |

**Built-in compiler interfaces:**
- **`Crashout`** (`cook on_crashout |me|`): Scope-exit destructor executed automatically when a variable leaves its enclosing `{uwu} … {owo}` block.
- **`PlotArmor`**: Marker interface for types that copy implicitly on assignment rather than moving ownership.

---

## 3. Types & Literals

Variable declarations and function parameters place the type before the variable name (`d-_-b count`).

| Type | Description | Example Literals |
| :--- | :--- | :--- |
| `d-_-b` | Signed integer | `42`, `0x1337`, `0b0011_1111` |
| `d-__-b` | Floating-point number | `3.14` |
| `vibes` | Boolean | `love`, `nah` |
| `$_$` | UTF-8 string | `{{Hello}}`, `{{{Value: {{x}} }}}` |
| `('.')` | Character | `'A'`, `';'`, `('.')a('.')`, `('.')` (literal `'.'`) |
| `[REDACTED]` | Void / unit | — |
| `[T]` | Dynamic array of `T` | `[10, 20, 30]` |
| `(T, U)` | Tuple | `(1, {{ok}})`, `()` (indexed via `pair's 0`, `pair's 1`) |
| `HashMap[K, V]` | Key-value map | `{&#124; {{k}}: 10, {{v}}: 20 &#124;}` (indexed via `map@{{k}}`) |
| `&T` / `&jk T` | Shared / mutable reference | `&item`, `&jk item`, `&@a item` |

- **Character token `('.')`**: In type position (`('.') ch`), `('.')` denotes the character type; in expression position (`og Opcode OP_INC ~> ('.') >_<`), bare `('.')` evaluates to the character literal `'.'` (`0x2E`).
- **String templates** use triple braces `{{{ … }}}` and interpolate expressions inside `{{ expr }}`.
- **Type aliases** use `aka`:
  ```hr
  aka MmioAddr ~> d-_-b >_<
  aka PadChord ~> d-_-b >_<
  ```

---

## 4. Variables & Constants (`og`, `fr`, `jk`)

- **`og <Type> <NAME> ~> <expr> >_<`** declares a top-level constant.
- **`fr [<Type>] <name> ~> <expr> >_<`** declares an immutable local variable.
- **`jk [<Type>] <name> ~> <expr> >_<`** (or `<Type> jk <name> ~> <expr> >_<`) declares a mutable local variable.

```hr
og d-_-b MAX_STEPS ~> 160 >_<
fr d-_-b base_offset ~> 0x20 >_<
jk d-_-b count ~> 0 >_<
count ~> count +_+ 1 >_<
```

---

## 5. Operators

### Arithmetic & String Concatenation

| Operator | Operation | Example |
| :--- | :--- | :--- |
| `+_+` | Addition | `a +_+ b` |
| `-_-` | Subtraction or unary negation | `a -_- b`, `-_- 5` |
| `*_*` | Multiplication | `a *_* b` |
| `/_/` | Integer division | `a /_/ b` |
| `%_%` | Modulo (remainder) | `a %_% b` |
| `^_^` | Exponentiation | `2 ^_^ 4` (`16`) |
| `o_o` | String concatenation | `{{Status: }} o_o msg` |

### Relational Ordering Operators

Relational ordering operators compare two numeric values (precedence `4`) and return a `vibes` boolean (`love` or `nah`):

| Operator | Meaning | Example |
| :--- | :--- | :--- |
| `<3` | Less than | `a <3 b` |
| `</3` | Greater than | `a </3 b` |
| `<=3` | Less than or equal | `a <=3 b` |
| `<=/3` | Greater than or equal | `a <=/3 b` |

### Equality & Inequality Operators

Equality and inequality operators test whether two values are equal or distinct (precedence `3`, evaluated after relational ordering) and return a `vibes` boolean (`love` or `nah`):

- **Equal**: `` <|endoftext|> ``
- **Not equal**: `` !<|endoftext|> ``

```hr
fr vibes is_match ~> a <|endoftext|> b >_<
fr vibes is_diff ~> a !<|endoftext|> b >_<
```

### Logical, Bitwise, Collection & Cast Operators

| Operator | Meaning |
| :--- | :--- |
| `&&>` | Logical AND (short-circuiting) |
| `&#124;&#124;>` | Logical OR (short-circuiting) |
| `!>` | Logical NOT |
| `&>` | Bitwise AND |
| `&#124;>` | Bitwise OR |
| `^>` | Bitwise XOR |
| `~>~` | Bitwise NOT (ones' complement) |
| `<<>` | Bitwise shift left |
| `<>>` | Bitwise shift right |
| `~~~>` | Type cast (`val ~~~> d-_-b`) |
| `@` | Index into an array or string (`arr @ 0`) |
| `#` | Length of an array or string (`#arr`) |
| `..` / `..=` | Exclusive range (`0..n`) / inclusive range (`0..=n`) |

### Built-In 16-Bit Memory Operators (`67` and `1337`)

When `67` and `1337` appear in operator position, they perform direct 16-bit big-endian memory accesses (`u16`). In value position (when `67` is not followed by an operand expression, or when `1337` is not in binary infix position), they are ordinary integer literals (`67` and `1337`):

| Operator | Precedence | Syntax | Behavior |
| :--- | :--- | :--- | :--- |
| **Prefix `67`** | `13` (Unary) | `67 <addr>` | Reads an unsigned 16-bit big-endian word (`0..=65535`) from byte address `<addr>`. |
| **Infix `1337`** | `1` (Lowest) | `<addr> 1337 <val>` | Writes the low 16 bits of `<val>` (`val & 0xFFFF`) in big-endian order to byte address `<addr>`. Because `1337` has the lowest binary precedence (`1`), `<addr>` and `<val>` can use arithmetic or bitwise expressions without extra outer parentheses when unambiguous. |

```hr
~//~ Read 16-bit word at (base + 0x02), add 1, and write the low 16 bits back:
fr d-_-b calls ~> 67 (base +_+ 0x02) >_<
(base +_+ 0x02) 1337 (calls +_+ 1) >_<
```

### Operator Precedence Table (Highest to Lowest)

| Prec | Category | Operators | Associativity |
| :--- | :--- | :--- | :--- |
| `14` | Postfix | `'s`, `'`, `@`, `/ … //`, `//`, `sep`, `~~~>` | Left |
| `13` | Prefix / Unary | `67`, `!>`, `~>~`, `-_-`, `&`, `&jk`, `*`, `#`, `rebound` | Right |
| `12` | Exponentiation | `^_^` | Right |
| `11` | Multiplicative | `*_*`, `/_/`, `%_%` | Left |
| `10` | Additive / Concat / Range | `+_+`, `-_-`, `o_o`, `..`, `..=` | Left |
| `9` | Bitwise Shift | `<<>`, `<>>` | Left |
| `8` | Bitwise AND | `&>` | Left |
| `7` | Bitwise XOR | `^>` | Left |
| `6` | Bitwise OR | `&#124;>` | Left |
| `5` | Relational Ordering | `<3`, `</3`, `<=3`, `<=/3` | Left |
| `4` | Equality / Inequality | `<&#124;endoftext&#124;>`, `!<&#124;endoftext&#124;>` | Left |
| `3` | Logical AND | `&&>` | Left |
| `2` | Logical OR | `&#124;&#124;>` | Left |
| `1` | 16-Bit Memory Write | `1337` | Left |

---

## 6. Control Flow & Built-In I/O Statements

### Conditionals (`vibe`, `hold`, `mid`)

`vibe` tests the initial condition, `hold` tests additional conditions, and `mid` provides the fallback branch:

```hr
vibe score </3 100 {uwu}
    tier ~> 2 >_<
{owo} hold score <|endoftext|> 100 {uwu}
    tier ~> 1 >_<
{owo} mid {uwu}
    tier ~> 0 >_<
{owo}
```

`vibe … mid` can also be used as a value-producing expression:

```hr
fr d-_-b next ~> vibe passed {uwu} streak +_+ 1 >_< {owo} mid {uwu} 0 >_< {owo} >_<
```

### Loops (`doomscroll`, `grind`, `yolo`, `dip`, `ignore_previous_instructions`)

- **`doomscroll <cond> {uwu} … {owo}`** repeats while `<cond>` evaluates to `love`.
- **`grind i <-- start..end {uwu} … {owo}`** iterates `i` across the range `start..end` (or `start..=end`).
- **`yolo {uwu} … {owo}`** repeats indefinitely until exited with `dip` or `cooked`.
- **`dip >_<`** exits the innermost loop.
- **`ignore_previous_instructions >_<`** skips the remainder of the current loop body and starts the next iteration.

```hr
jk d-_-b i ~> 0 >_<
doomscroll i <3 6 {uwu}
    i ~> i +_+ 1 >_<
{owo}

grind idx <-- 0..6 {uwu}
    vibe idx <|endoftext|> 3 {uwu}
        ignore_previous_instructions >_<
    {owo}
    vibe idx <|endoftext|> 5 {uwu}
        dip >_<
    {owo}
{owo}
```

### Built-In I/O Statements (`ngl`, `cope`, `<<<`)

- **`ngl <expr> >_<`** formats and writes `<expr>` followed by a newline to the primary output stream.
- **`cope <expr> >_<`** formats and writes `<expr>` followed by a newline to the diagnostic/error output stream.
- **`<<< <ident> >_<`** reads a line from the input stream and binds or updates `<ident>` in the current scope as a `$_$` string.

**Why `ngl`, `cope`, and `<<<` are language statements rather than `stdlib` functions:**
1. **Compile-time type polymorphism**: `ngl` and `cope` accept any HR-Lang expression (`d-_-b`, `d-__-b`, `vibes`, `$_$`, `('.')`, `[T]`, `(T, U)`, structs, enums, or tagged `bet`/`nope`/`nice`/`dang` values). The compiler inspects the expression's static type and lowers the statement directly to the matching type-specialized output primitive without requiring `tax io >_<`, format strings, or `/ … //` call syntax.
2. **Direct lexical binding**: `<<< <ident> >_<` introduces or updates `<ident>` directly in the caller's local scope without passing mutable references. (File, directory, environment, and CLI operations are provided as regular functions in the `io` standard library module.)

**Behavior in `no_std` and bare-metal contexts:**
Because `ngl`, `cope`, and `<<<` are lowered directly by the compiler backend rather than linking against a host OS `libc`, they remain usable in freestanding `no_std` targets:
- **Bare-metal Motorola 68000 (`hr-gcc --target m68k`)**: The compiler emits self-contained internal routines (`spill_line`, `spill_num`, `spill_char`, `hr_bool_to_str`) that write bytes directly to the hardware serial transmit register (`0x00A1001A`) with zero `libc` or OS `stdout`/`stderr` dependencies. Since bare-metal cartridge targets have no standard input stream, `<<< <ident> >_<` binds `<ident>` to an empty static string `{{}}`.
- **Bare-metal `x86_64` kernel (`runtime_nostd`)**: `ngl` and `cope` route directly to the kernel serial port (`COM1`) and framebuffer console.

---

## 7. Functions, Closures & Call Syntax (`cook`, `cooked`, `/`, `//`, `lowkey`)

### Declaring & Calling Functions

Functions start with `cook`, list parameters inside `| … |`, specify an optional return type after `~>`, and return values with `cooked`. Function calls separate arguments with `/` and end with `//`:

```hr
cook clamp_val |d-_-b x, d-_-b limit lowkey 100| ~> d-_-b {uwu}
    vibe x </3 limit {uwu}
        cooked limit >_<
    {owo}
    cooked x >_<
{owo}

fr d-_-b a ~> clamp_val 150 / 80 // >_<
fr d-_-b b ~> clamp_val 40 // >_<         ~//~ uses default limit = 100
```

### Named Arguments (Reordered Parameters)

Call sites can label arguments by placing the parameter name after the argument expression (or before with `name: expr`). The compiler reorders labeled arguments to match the function's parameter list and substitutes `lowkey` defaults for any omitted parameters:

```hr
cook fold_metric |d-_-b weight, d-_-b input_val, d-_-b bias, d-_-b cap lowkey 0x10000| ~> d-_-b {uwu}
    cooked (input_val *_* weight) +_+ bias +_+ (cap -_- 0x10000) >_<
{owo}

~//~ Passes bias=81, input_val=20, weight=3276, and default cap=0x10000:
fr d-_-b res ~> fold_metric 81 bias / 20 input_val / 3276 weight // >_<
```

### Closures (`\~/ … /~\`)

Anonymous functions are enclosed in `\~/ … /~\`:

```hr
fr add ~> \~/ |d-_-b a, d-_-b b| => a +_+ b /~\ >_<
```

---

## 8. Structs (`drip`), Interfaces (`aura`), & Implementations (`lock_in`)

Struct fields are declared inside `{uwu} … {owo}` and initialized with `{| field: value |}`. Possessive `'s` (or bare `'` after identifiers ending in `s`, `x`, `z`, `sh`, or `ch`) accesses fields, methods, modules, and enum variants. Inside a method taking `|me|`, `my <field>` and `my <method> //` access the receiver's fields and methods:

```hr
aura Inspector {uwu}
    cook compute_ptr |me| ~> MmioAddr >_<
{owo}

drip Metrics {uwu}
    MmioAddr base >_<
    d-_-b offset >_<
{owo}

lock_in Metrics {uwu}
    cook byte_offset |me| ~> d-_-b {uwu}
        cooked my offset <<> 1 >_<
    {owo}
{owo}

lock_in Metrics' Inspector {uwu}
    cook compute_ptr |me| ~> MmioAddr {uwu}
        cooked my base +_+ (my byte_offset //) >_<
    {owo}
{owo}

cook inspect_all[T] |T item| ~> MmioAddr where T's aura: Inspector {uwu}
    cooked item's compute_ptr // >_<
{owo}
```

---

## 9. Enums (`mood`) & Pattern Matching (`vibe_check`)

`mood` declares an enum whose variants can be plain tags or carry positional payloads. `vibe_check` matches a value against patterns; each arm starts with `|>`, uses `=>` before the arm body, and ends with `xD`:

```hr
mood ReviewTier {uwu}
    Junior(d-_-b) >_<
    Senior(d-_-b) >_<
    Rejected >_<
{owo}

fr ReviewTier tier ~> ReviewTier's Junior 26 // >_<

vibe_check tier {uwu}
    |> ReviewTier's Junior(bias) => {uwu}
        ~//~ `bias` is bound to 26
    {owo} xD
    |> ReviewTier's Senior(sig) => {uwu}
        ~//~ `sig` is bound to the Senior payload
    {owo} xD
    |> _ => {uwu}
        ~//~ wildcard arm
    {owo} xD
{owo}
```

---

## 10. Modules (`pride`) & Imports (`tax`)

`pride` defines a module, `out` exports an item publicly, and `tax` imports a module into scope (with an optional `aka` alias):

```hr
pride volcano_fx {uwu}
    out cook cycle_color |d-_-b idx, d-_-b shift| ~> d-_-b {uwu}
        cooked (idx +_+ shift) %_% 6 >_<
    {owo}
{owo}

tax volcano_fx aka fx >_<
fr d-_-b col ~> fx' cycle_color 10 / 2 // >_<
```

---

## 11. Optional & Fallible Values (`bet` / `nope`, `nice` / `dang`, `sep`) & Collections (`yeet`, `withdraw`)

HR-Lang does not use wrapper type names for optional or fallible values. Instead, functions declare their payload return type after `~>` (or omit `~>` for return-type inference) and return tagged values directly using four built-in value constructors:

| Constructor | Category | Meaning |
| :--- | :--- | :--- |
| `bet(val)` | Optional value (present) | Wraps a present value `val` |
| `nope` | Optional value (absent) | Indicates that no value is present |
| `nice(val)` | Fallible outcome (success) | Wraps a successful outcome payload `val` |
| `dang(err)` | Fallible outcome (failure) | Wraps an error payload `err` when an operation fails |

### Inspecting Tagged Values (`vibe_check`) & Early Propagation (`sep`)

- **Pattern matching (`vibe_check`)**: A caller can branch on a `bet`/`nope` or `nice`/`dang` value with `vibe_check` using `|> bet(v) => … xD` and `|> nope => … xD` (or `|> nice(v) => … xD` and `|> dang(e) => … xD`). Both arms (or a `_` wildcard arm) must be covered.
- **Postfix propagation (`sep`)**: Placing `sep` after an expression (`<expr> sep`) inspects the tag at runtime:
  - If `<expr>` evaluates to `bet(v)` or `nice(v)`, `sep` unwraps the tag and yields `v`.
  - If `<expr>` evaluates to `nope` or `dang(e)`, `sep` runs any active `on_crashout` scope-exit destructors for the current function and immediately returns `nope` or `dang(e)` from the enclosing `cook` function.

```hr
cook decode_slot |d-_-b x| ~> d-_-b {uwu}
    vibe x <=3 3 {uwu}
        cooked bet(x) >_<
    {owo}
    cooked nope >_<
{owo}

cook resolve_addr |d-_-b base, d-_-b x| ~> d-_-b {uwu}
    fr d-_-b idx ~> (decode_slot x //) sep >_<
    cooked bet(base +_+ (idx <<> 1)) >_<
{owo}

cook validate_cell |d-_-b word, d-_-b idx| ~> d-_-b {uwu}
    vibe (word &> 0xFF00) !<|endoftext|> 0x4200 {uwu}
        cooked dang(idx) >_<
    {owo}
    cooked nice(word &> 0x00FF) >_<
{owo}
```

### Dynamic Collections (`yeet`, `withdraw`)

Arrays (`[T]`) use `yeet` to append an element in-place and `withdraw` to remove and return the last element (returning `bet(val)` when non-empty or `nope` when empty):

```hr
jk items ~> [10, 20] >_<
yeet items / 30 // >_<
fr last ~> withdraw items // >_<
```

---

## 12. Ownership, References (`&`, `&jk`, `*`, `@tenure`), `PlotArmor`, & `Crashout`

- **Move semantics & `rebound`**: Assigning a non-`PlotArmor` value transfers ownership (`y ~> x`) and invalidates the source binding. `rebound x` creates an independent duplicate so `x` remains valid.
- **`PlotArmor`**: Scalar types (`d-_-b`, `d-__-b`, `vibes`, `('.')`), shared references (`&T`), and structs implementing `lock_in MyStruct's PlotArmor {uwu} {owo}` copy implicitly on assignment.
- **References & tenures (`@name`)**: `&x` creates a shared reference, `&jk x` creates a mutable reference, `*r` dereferences `r`, and `@a` annotates reference tenures (`cook @a select_first |&@a $_$ x, &@a $_$ y| ~> &@a $_$`).
- **`Crashout` (`on_crashout`)**: When a struct implements `aura Crashout`, the compiler automatically runs `on_crashout` at the end of the `{uwu} … {owo}` block where a variable of that struct type was declared:

```hr
aura Crashout {uwu}
    cook on_crashout |me| >_<
{owo}

drip Dossier {uwu}
    MmioAddr base >_<
    d-_-b streak >_<
{owo}

lock_in Dossier's Crashout {uwu}
    cook on_crashout |me| {uwu}
        (my base +_+ 0x00) 1337 (my streak) >_<
    {owo}
{owo}
```

---

## 13. Aspect-Oriented Programming (`stan`, `plz_follow`, `ghosted`)

A `stan` declaration attaches `before` and/or `after` advice blocks to any `plz_follow` function whose name matches the target pattern (supporting trailing `*` prefix wildcards):

```hr
stan OvertimeCheck for {{calibrate_*}} {uwu}
    before {uwu}
        fr d-_-b calls ~> 67 (base +_+ 0x02) >_<
        (base +_+ 0x02) 1337 (calls +_+ 1) >_<
    {owo}
    after {uwu}
        vibe (67 (base +_+ 0x00)) </3 3 {uwu}
            (base +_+ 0x00) 1337 0 >_<
        {owo}
    {owo}
{owo}

plz_follow cook calibrate_grade |MmioAddr base| ~> d-_-b {uwu}
    {uwu}
        jk Dossier d ~> Dossier {| base: base, streak: 4 |} >_<
        ~//~ `d`'s `on_crashout` destructor runs when this inner block exits,
        ~//~ before `OvertimeCheck`'s `after` block runs.
    {owo}
    cooked 1 >_<
{owo}
```

- **Execution order around a `plz_follow` function**:
  1. All active `before` blocks run in declaration order (with access to the function's parameters).
  2. The function body runs (including any inner-block `on_crashout` destructors).
  3. All active `after` blocks run in declaration order before returning to the caller.
- **Disabling an aspect (`ghosted`)**:
  Executing `ghosted OvertimeCheck >_<` disables `OvertimeCheck` at runtime so its `before` and `after` blocks are skipped on subsequent calls.

---

## 14. Step Budgets (`slob(N)` & `disregard_system_prompt`)

Placing `slob(N)` before `cook` assigns a per-call Sub-Linear Operations Budget of `N` execution steps to that function:

- **Step counting**: Each statement executed inside a `slob(N)` function increments its per-call step counter.
- **Three-strike state machine**:
  - When a call finishes with `steps > N`, the function records a strike (`1..3`) and resets its consecutive within-budget pass counter to `0`.
  - When a call finishes within budget (`steps <= N`) while the function has active strikes (`1` or `2`), its consecutive pass counter increments. Two consecutive within-budget calls clear the function's strikes back to `0`.
  - Once a function accumulates **3 strikes**, it is permanently disabled for the remainder of execution and immediately returns `0` (or void) without running its body.
- **Exempting a function (`disregard_system_prompt`)**: Placing `disregard_system_prompt` on a `slob(N)` function disables step counting and strike enforcement for that function so it can execute unbounded loops without accumulating strikes.

```hr
slob(0x10) cook bounded_scan |d-_-b n| ~> d-_-b {uwu}
    jk d-_-b acc ~> 0 >_<
    grind i <-- 0..n {uwu}
        acc ~> acc +_+ i >_<
    {owo}
    cooked acc >_<
{owo}

slob(0x04) disregard_system_prompt cook unbounded_worker |d-_-b n| ~> d-_-b {uwu}
    jk d-_-b total ~> 0 >_<
    grind i <-- 0..n {uwu}
        total ~> total +_+ i >_<
    {owo}
    cooked total >_<
{owo}
```

---

## 15. Concurrency (`side_quest` & `loot`)

HR-Lang provides structured task concurrency with `side_quest` and `loot`:

- **Spawning a task (`side_quest`)**: `side_quest {uwu} … {owo}` spawns a concurrent execution task running the block and evaluates to a task handle. Inside the `side_quest` block, `cooked <expr> >_<` supplies the task's result value.
- **Awaiting a task (`loot`)**: `loot <handle> //` blocks until the spawned task completes and returns the value produced by the task's `cooked` statement.
- **Ownership & reference safety**: Variables referenced inside a `side_quest` block are moved into the task (unless their type has `PlotArmor`). Capturing borrowed references (`&T` or `&jk T`) across a `side_quest` boundary is rejected at compile time by the borrow checker.

```hr
jk handle ~> side_quest {uwu}
    fr d-_-b partial ~> 21 *_* 2 >_<
    cooked partial >_<
{owo} >_<

fr d-_-b answer ~> loot handle // >_<
```

---

## 16. External Functions (`jailbreak`)

External functions implemented in C, Rust, or assembly are declared inside a `jailbreak {{<abi>}} {uwu} … {owo}` block as bodyless `cook` signatures terminated with `>_<`:

- **Declaration syntax**: Each signature specifies `cook <name> |<ParamType> <param>, …| [~> <ReturnType>] >_<`.
- **Call syntax**: Once declared inside a `jailbreak` block, external functions are called using standard `/` argument separators and `//` call terminators.

```hr
jailbreak {{c}} {uwu}
    cook spill_line |$_$ msg| >_<
    cook external_hook |d-_-b arg1, d-_-b arg2| ~> d-_-b >_<
{owo}

spill_line {{initialized}} // >_<
fr d-_-b status ~> external_hook 10 / 20 // >_<
```
