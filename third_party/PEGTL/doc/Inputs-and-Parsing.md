# Inputs and Parsing

Assuming that the [grammar rules](Rules-and-Grammars.md) are ready, and the [actions and states](Actions-and-States.md) prepared, performing a parsing run consists of two steps:

1. Constructing an *input* class that represents the to-be-parsed data.
2. Calling a PEGTL *parse* function with the input (and any states).

```c++
using namespace tao::pegtl;

struct my_grammar : ...;

template< typename Rule >
struct my_actions : nothing< Rule > {};

// Specialisations of my_actions as required...

bool my_parse( const std::string& filename, my_state& state )
{
   file_input<> in( filename );
   return parse< my_grammar, my_actions >( in, state );
}
```

In the context of PEGTL input classes and positions, `source` is a string that identifies where the to-be-parsed data comes from.
For example when parsing a file, the filename is the source.

All classes and functions on this page are in namespace `tao::pegtl`.

## Contents

* [Tracking Mode](#tracking-mode)
* [Line Ending](#line-ending)
* [Source](#source)
* [File Input](#file-input)
* [Memory Input](#memory-input)
* [String Input](#string-input)
* [Stream Inputs](#stream-inputs)
* [Argument Input](#argument-input)
* [Parse Function](#parse-function)
* [Nested Parsing](#nested-parsing)
* [Incremental Input](#incremental-input)
  * [Grammars and Buffering](#grammars-and-buffering)
  * [Custom Data Sources](#custom-data-sources)

## Tracking Mode

Some input classes allow a choice of tracking mode, or whether the `byte`, `line` and `byte_in_line` counters are continuously updated during a parsing run with `tracking_mode::IMMEDIATE`, or only calculated on-demand in the `position()`-method by scanning the complete input again with `tracking_mode::LAZY`.

Lazy tracking is recommended when the position is used very infrequently, for example only in the case of throwing a `parse_error`.

Immediate tracking is recommended when the position is used frequently and/or in non-exceptional cases, for example when annotating every AST node with the line number.

## Line Ending

All input classes allow the choice of which line endings should be recognised by the `eol` and `eolf` rules, and used for line counting.
The supported line endings are `cr`, a single carriage-return/`"\r"`/`0x0d` character as used on classic Mac OS, `lf`, a single line-feed/`"\n"`/`0x0a` as used on Unix, Linux, Mac OS X and macOS, and `crlf`, a sequence of both as used on MS-DOS and Windows.

The default template argument for all input classes is `eol::lf_crlf` which recognises both Unix and MS-DOS line endings.
The supplied alternatives are `eol::cr`, `eol::lf`, `eol::crlf` and `eol::cr_crlf`.

## Source

Some input classes allow a choice of how to store the source parameter, with the default being a `std::string`.
When creating many instances of an input class, it can be changed to a non-owning `const char*` to optimise away the memory allocation performed by `std::string`.

## File Input

The classes `file_input<>`, `read_input<>` and, on supported platforms, `mmap_input<>`, can be used to parse the contents of a file.

* `read_input<>` uses C "stdio" facilities to read the file.
* `mmap_input<>` uses `mmap(2)` and is available on POSIX compliant systems.
* `file_input<>` is a type alias for `mmap_input<>` when available, and `read_input<>` otherwise.

All file input classes take a single argument, the filename, which can be supplied as `std::string` or `const char*`.
They immediately make available the complete contents of the file; `read_input<>` reads the entire file upon construction.

```c++
template< tracking_mode P = tracking_mode::IMMEDIATE, typename Eol = eol::lf_crlf >
struct read_input
{
   explicit read_input( const char* filename );
   explicit read_input( const std::string& filename );
};

template< tracking_mode P = tracking_mode::IMMEDIATE, typename Eol = eol::lf_crlf >
struct mmap_input  // Only on POSIX compliant systems.
{
   explicit mmap_input( const char* filename );
   explicit mmap_input( const std::string& filename );
};

template< tracking_mode P = tracking_mode::IMMEDIATE, typename Eol = eol::lf_crlf >
using file_input = mmap_input< P, Eol >;  // Or read_input when no mmap_input available.
```

Note that the implementation of the constructors is different than shown.
They should be used "as if" this was the actual signature.

## Memory Input

The class `memory_input<>` can be used to parse existing contiguous blocks of memory like the contents of a `std::string`.
The input **neither copies the data nor takes ownership, it only keeps pointers**.
The various constructors accept the to-be-parsed data and the source in different formats.

The constructors that only takes a `const char* begin` for the data uses `std::strlen()` to determine the length.
It will therefore *only* work correctly with data that is terminated with a 0-byte (and does not contain embedded 0-bytes, which are otherwise fine).

The constructors that take additional `byte`, `line` and `byte_in_line` arguments initialise the internal counters with the supplied values, rather than the defaults of `0`, `1` and `0`.

```c++
template< tracking_mode P = tracking_mode::IMMEDIATE, typename Eol = eol::lf_crlf, typename Source = std::string >
class memory_input
{
   template< typename T >
   memory_input( const internal::iterator& iter, const char* end, T&& source ) noexcept(...);

   template< typename T >
   memory_input( const char* begin, const char* end, T&& source ) noexcept(...);

   template< typename T >
   memory_input( const char* begin, const std::size_t size, T&& source ) noexcept(...);

   template< typename T >
   memory_input( const std::string& string, T&& source ) noexcept(...);

   template< typename T >
   memory_input( const char* begin, T&& source ) noexcept(...);

   template< typename T >
   memory_input( const char* begin, const char* end, T&& source,
                 const std::size_t byte, const std::size_t line, const std::size_t byte_in_line ) noexcept(...);
};
```

Note that `noexcept(...)` is a conditional noexcept-specification, depending on whether the construction of the source stored in the class can throw given the perfectly-forwarded parameter `source`. Technically, it is implemented as `noexcept( std::is_nothrow_constructible< Source, T&& >::value )`.

With the default `Source` type of `std::string`, the `source` parameter to the constructors is usually a `const char*` or (any reference to) a `std::string`, but anything that can be used to construct a `std::string` will work. When `Source` is set to `const char*` then only a `const char *` (or something that can implicitly be converted to one) will work.

The implementation of the constructors is different than shown.
They should be used "as if" this was the actual signature.


## String Input

The class `string_input<>` can also be used to parse a `std::string`.
Unlike class `memory_input<>`, this class stores a copied (or moved) version of the data for which it takes ownership.

```c++
template< tracking_mode P = tracking_mode::IMMEDIATE, typename Eol = eol::lf_crlf, typename Source = std::string >
class string_input
{
   template< typename V, typename T >
   string_input( V&& data, T&& source ) noexcept(...);

   template< typename V, typename T >
   string_input( V&& data, T&& source,
                 const std::size_t byte, const std::size_t line, const std::size_t byte_in_line ) noexcept(...);
};
```

Note that the implementation of the constructors is different than shown.
They should be used "as if" this was the actual signature.

## Stream Inputs

The classes `cstream_input<>` and `istream_input<>` can be used to parse data from C-streams (`std::FILE*`) and C++-streams (`std::istream`), respectively.
Unlike the file inputs above, they internally use `buffer_input<>` and therefore do *not* read the complete stream upon construction.

They all have a single constructor that takes a stream, the maximum buffer size, and the name of the source.
Note that these classes only keep a pointer/reference to the stream and do **not** take ownership; in particular `cstream_input<>` does **not** call `std::close()`.

See [Incremental Input](#incremental-input) for details on the `maximum` argument, and how to prepare a grammar for incremental input support using the `discard`-rule.

```c++
template< typename Eol = eol::lf_crlf >
struct cstream_input
{
   cstream_input( std::FILE* stream, const std::size_t maximum, const char* source );
   cstream_input( std::FILE* stream, const std::size_t maximum, const std::string& source );
};

template< typename Eol = eol::lf_crlf >
struct istream_input
{
   istream_input( std::istream& stream, const std::size_t maximum, const char* source );
   istream_input( std::istream& stream, const std::size_t maximum, const std::string& source );
};
```

Note that the implementation of the constructors is different than shown.
They should be used "as if" this was the actual signature.

## Argument Input

The class `argv_input<>` can be used to parse a string passed from the command line.

```c++
template< tracking_mode P = tracking_mode::IMMEDIATE, typename Eol = eol::lf_crlf >
class argv_input
{
   argv_input( char** argv, const std::size_t n );
   argv_input( char** argv, const std::size_t n, const char* source );
   argv_input( char** argv, const std::size_t n, const std::string& source );
};
```

If no `source` is given, the source is set to `"argv[N]"` where N is the string representation of `n`.

Note that the implementation of the constructors is different than shown.
They should be used "as if" this was the actual signature.

## Parse Function

The parse functions accept the following template parameters and arguments:

- The [`Rule` class](Rules-and-Grammars.md) represents the top-level parsing rule of the grammar and is mandatory.
- The [`Action<>` class template](Actions-and-States.md) is required to actually do something during a parsing run.
- The [`Control<>` class template](Control-and-Debug.md) is only required for grammar debugging or some advanced uses.
- The [`States`](Actions-and-States) are the types of the objects that are passed to all actions and control hooks.

Additionally, two enumeration values can be used to control the behaviour:

- The `apply_mode` which can also be set to `NOTHING` in order to disable action invocations, just like the `disable<>` rule does.
- The `rewind_mode` which can also be set to `DONTCARE` in order to not require rewinding of the input on local failure, a micro optimisation.

The result of a parsing run, i.e. an invocation of `tao::pegtl::parse()`, can be either

- *success*, a return value of `true`,
- *local failure*, a return value of `false`,
- *global failure*, an exception of type `tao::pegtl::parse_error`, or
- any other exception thrown by the input class or an action method.

```c++
template< typename Rule,
          template< typename... > class Action = nothing,
          template< typename... > class Control = normal,
          apply_mode A = apply_mode::ACTION,
          rewind_mode M = rewind_mode::REQUIRED,
          typename Input,
          typename... States >
bool parse( Input& in,
            States&&... st );
```

## Nested Parsing

Nested parsing refers to an (inner) parsing run that is performed "in the middle of" another (outer) parsing run, for example when one file "includes" another file.

The difference to the regular `tao::pegtl::parse()` function is that `tao::pegtl::parse_nested()` takes care of adding to the `std::vector` of `tao::pegtl::position` objects in the exception class `tao::pegtl::parse_error`.
This allows generating error messages of the form "error in file F1 line L1 included from file F2 line L2...".

Calling `parse_nested()` requires one additional argument compared to `parse()`, the input from the outer parsing run as first argument.
Everything else remains the same.

```c++
template< typename Rule,
          template< typename... > class Action = nothing,
          template< typename... > class Control = normal,
          apply_mode A = apply_mode::ACTION,
          rewind_mode M = rewind_mode::REQUIRED,
          typename Outer,
          typename Input,
          typename... States >
bool parse_nested( const Outer& oi,
                   Input& in,
                   States&&... st );
```

## Incremental Input

The PEGTL is designed and optimised for parsing single contiguous blocks of memory, e.g. the contents of a file made available via `mmap(2)`, or the contents of a `std::string`.

In cases where the input does not fit into memory, or there are other reasons to not create a single memory block containing all input data, it is possible, with a little help from the grammar, to perform incremental parsing, where the data is incrementally made available, e.g. when reading from a stream.

### Grammars and Buffering

A buffer is used to keep a portion of the input data in a contiguous memory block.
The buffer is allocated at the begin of the parsing run with a user-supplied maximum size.

The maximum buffer size usually depends on the grammar, the actions, and the input data.
It must be chosen large enough to keep the data required for (a) any backtracking, and (b) all action invocations.

The buffer is automatically filled by the parsing rules that require input data, however **discarding data from the buffer is** (currently) **not automatic**:
The grammar has to call [`discard`](Rule-Reference.md#discard) in appropriate places to free the buffer again.

More precisely, each rule that uses one of the following methods on the input will implicitly make a call to `tao::pegtl::buffer_input<>::require( amount )`.
(The `empty()`-method uses a hard-coded `amount` of 1.)

```c++
namespace tao
{
   namespace pegtl
   {
      template< class Reader, typename Eol = eol::lf_crlf >
      class buffer_input
      {
         empty();
         size( const std::size_t amount );
         end( const std::size_t amount );
         ...
      };
   }
}
```

This tells the input that a rule wants to inspect and/or consume a certain `amount` of input bytes, and it will attempt to fill the buffer accordingly.
The returned `size()`, and the distance from `begin()` to `end()`, can also be larger than the requested amount.

For example, the rule `tao::pegtl::ascii::eol`, which (usually) checks for both `"\r\n"` and "`\n`", calls `size(2)` because it needs to inspect up to two bytes.
Depending on whether the result of `size(2)` is `0`, `1` or `2`, it will choose which of these two sequences it can attempt to match.
The number of actually consumed bytes can again be `0`, `1` or `2`, depending on whether they match a valid `eol`-sequence.

To prevent the buffer from overflowing, the `discard()`-method of class `tao::pegtl::buffer_input` must be called, usually by using the `discard` parsing rule.
It discards all data in the buffer that precedes the current `begin()`-point, and any remaining data is moved to the beginning of the buffer.
**A `discard` invalidates all pointers to the input's data.**

```
Buffer Memory Layout

B                   begin of buffer space
:
B + X               begin of unconsumed buffered data as per begin()
:
B + X + size( 0 )   end of unconsumed buffered data as per end( 0 )
:
B + maximum         end of buffer space
```

A discard moves the data in the buffer such that `X` is zero, and updates `begin()` to point at the beginning of the buffer.

### Custom Data Sources

The PEGTL contains a set of stream parser input classes that take care of everything (except discarding data from the buffer, see above) for certain data sources.
In order to support other data sources, it is necessary to create a custom input class, usually by creating a suitable *reader* class that can be supplied as template argument to class `tao::pegtl::buffer_input<>`.

The reader class can be anything that can be called like the following standard function wrapper:

```c++
std::function< std::size_t( char* buffer, const std::size_t length ) >
```

The arguments and return value are similar to other `read()`-style functions:
Attempt to read up to `length` bytes into the memory pointed to by `buffer` and return the number of bytes actually read.
Reaching the end of the input should be the only reason for the reader to return zero.

The steps required to use a custom reader for a parsing run are:

1. Create a suitable reader class `Reader` (or function).
2. Create an instance of class `tao::pegtl::buffer_input< Reader >`, using the fact that the `buffer_input`'s constructor can pass arbitrary arguments to the embedded reader instance.
3. Call `tao::pegtl::parse()` (or `tao::pegtl::parse_nested()`) with the previously created `buffer_input` instance as first argument.

The included examples for C- and C++-style streams can also be used as reference on how to create and use suitable readers, simply `grep(1)` for `cstream_reader` and `istream_reader` (and `cstring_reader`) in the PEGTL source code.

Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
