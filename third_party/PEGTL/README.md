## Welcome to the PEGTL

[![Release](https://img.shields.io/github/release/taocpp/PEGTL.svg)](https://github.com/taocpp/PEGTL/releases/latest)
[![TravisCI](https://travis-ci.org/taocpp/PEGTL.svg)](https://travis-ci.org/taocpp/PEGTL)
[![AppVeyor](https://ci.appveyor.com/api/projects/status/github/taocpp/PEGTL?svg=true)](https://ci.appveyor.com/project/taocpp/PEGTL)
[![Doozer.io](https://doozer.io/badge/taocpp/PEGTL/buildstatus/master)](https://doozer.io/user/taocpp/PEGTL)
[![Coverage](https://img.shields.io/coveralls/taocpp/PEGTL.svg)](https://coveralls.io/github/taocpp/PEGTL)

The Parsing Expression Grammar Template Library (PEGTL) is a zero-dependency
C++11 header-only parser combinator library for creating parsers according to a
[Parsing Expression Grammar](http://en.wikipedia.org/wiki/Parsing_expression_grammar)
(PEG).

### Documentation

*   [Version 2.x Documentation](doc/README.md)
*   [Version 1.3 Documentation](https://github.com/taocpp/PEGTL/blob/1.3.x/doc/README.md)

### Introduction

Grammars are written as regular C++ code, created with template programming (not
template meta programming), i.e. nested template instantiations that naturally
correspond to the inductive definition of PEGs (and other parser-combinator
approaches).

A comprehensive set of [parser rules](doc/Rule-Reference.md) that can be
combined and extended by the user is included, as are mechanisms for debugging
grammars, and for attaching user-defined [actions](doc/Actions-and-States.md) to
grammar rules. Here is an example of how a PEG grammar rule is implemented as
C++ class with the PEGTL.

```c++
// PEG rule for integers consisting of a non-empty
// sequence of digits with an optional sign:

// integer ::= ( '+' / '-' )? digit+

// The same parsing rule implemented with the PEGTL:

using namespace tao::pegtl;

struct integer : seq< opt< one< '+', '-' > >, plus< digit > > {};
```

PEGs are superficially similar to Context-Free Grammars (CFGs), however the more
deterministic nature of PEGs gives rise to some very important differences. The
included [grammar analysis](doc/Grammar-Analysis.md) finds several typical
errors in PEGs, including left recursion.

### Design

The PEGTL is designed to be "lean and mean", the core library consists of
approximately 5000 lines of code. Emphasis is on simplicity and efficiency,
preferring a well-tuned simple approach over complicated optimisations.

The PEGTL is mostly concerned with parsing combinators and grammar rules, and
with giving the user of the library (the possibility of) full control over all
other aspects of a parsing run. Whether/which actions are taken, and
whether/which data structures are created during a parsing run, is entirely up
to the user.

Included are some [examples](doc/Contrib-and-Examples.md#examples) for typical
situation like unescaping escape sequences in strings, building a generic
[JSON](http://www.json.org/) data structure, and on-the-fly evaluation of
arithmetic expressions.

Through the use of template programming and template specialisations it is
possible to write a grammar once, and use it in multiple ways with different
(semantic) actions in different (or the same) parsing runs.

Unlike [Antlr](http://www.antlr.org/) and
Yacc/[Bison](http://www.gnu.org/software/bison/), the grammar is expressed in
C++ and is part of the C++ source code. Also, with the PEG formalism the
separation into lexer and parser stages is usually dropped -- everything is done
in a single grammar.

Unlike [Spirit](http://boost-spirit.com/), the grammar is implemented with
compile-time template instantiations rather than run-time operator calls. This
leads to slightly increased compile times as the C++ compiler is given the task
of optimising PEGTL grammars.

### Status

The master branch of the PEGTL is stable in the sense that all known bugs are
fixed and all unit tests run without errors.

Each commit is automatically tested with multiple architectures, operating
systems, compilers, and versions thereof.

*   Windows

    *   Visual Studio 2015 (x86, x64)
    *   Visual Studio 2017 (x86, x64)
    *   MinGW (i686), GCC 5
    *   MinGW-w64 (i686), GCC 5, 6
    *   MinGW-w64 (x86_64), GCC 6

*   Mac OS X / macOS (using libc++)

    *   Mac OS X 10.10, Xcode 6.4
    *   Mac OS X 10.11, Xcode 7.3
    *   macOS 10.12, Xcode 8.3
    *   macOS 10.12, Xcode 9

*   Linux (using libstdc++)

    *   Debian 8 (i386), GCC 4.9
    *   Ubuntu 12.04 LTS (amd64), Clang 3.4, 3.7
    *   Ubuntu 14.04 LTS (amd64), GCC 4.8, 4.9, 5, 6, 7
    *   Ubuntu 14.04 LTS (amd64), Clang 3.5, 3.6, 3.8, 3.9, 4.0, 5.0
    *   Ubuntu 14.04 LTS (i386, amd64), GCC 4.8
    *   Ubuntu 16.04 LTS (i386, amd64, armhf, arm64), GCC 5
    *   Fedora 24 (x86_64), GCC 6
    *   Fedora 24 (x86_64), Clang 3.8

*   Android

    *   Android 5.1

Additionally, each commit is checked with GCC's and Clang's sanitizers as well
as [`valgrind`](http://valgrind.org/). Code coverage is automatically measured
and the unit tests cover 100% of the core library code (for releases).

[Releases](https://github.com/taocpp/PEGTL/releases) are done in accordance with
[Semantic Versioning](http://semver.org/). Incompatible API changes are *only*
allowed to occur between major versions. For details see the
[changelog](doc/Changelog.md).

### Thank You

*   Christopher Diggins and the YARD parser for the general idea.
*   George Makrydakis for the
    [inspiration](https://github.com/irrequietus/typestring) to
    `TAOCPP_PEGTL_STRING`.
*   Johannes Overmann for his invaluable
    [`streplace`](https://code.google.com/p/streplace/) command-line tool.
*   Jörg-Christian Böhme for improving the Android CI build.
*   Kai Wolf for help with CMake.
*   Kenneth Geisshirt for Android compatibility and Android CI.
*   Kuzma Shapran for EOL testing and fixes.
*   Michael Becker for help with CMake.
*   Paulo Custodio for Windows-related fixes.
*   Sam Hocevar for contributing Visual Studio 2015 compatibility.
*   Stephan Beal for the bug reports, suggestions and discussions.
*   Sven Johannsen for help with CMake.
*   Zhihao Yuan for fixing several warnings when compiling with Visual
    Studio 2015.

### Contact

For questions and suggestions regarding the PEGTL, success or failure stories,
and any other kind of feedback, please feel free to contact the authors at
`taocpp(at)icemx.net`.

### License

The PEGTL is certified
[Open Source](http://www.opensource.org/docs/definition.html) software. It may
be used for any purpose, including commercial purposes, at absolutely no cost.
It is distributed under the terms of the
[MIT license](http://www.opensource.org/licenses/mit-license.html) reproduced
here.

> Copyright (c) 2007-2017 Dr. Colin Hirsch and Daniel Frey
>
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.
