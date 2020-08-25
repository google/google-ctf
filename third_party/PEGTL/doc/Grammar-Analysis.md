# Grammar Analysis

The PEGTL contains an `analyze()`-function that checks a grammar for rules that can go into an infinite loop without consuming input.

Unfortunately, given the expressive power of PEGs and the possibility of arbitrary custom combinator rules, it is impossible to detect *all* kinds of infinite loops.

It does however catch most cases of left-recursion that are typical for grammars converted from CFGs or other formalisms that gracefully handle left-recursion.

## Rule Analysis

In order to run an analysis on a grammar it is necessary to explicitly include `<tao/pegtl/analyze.hpp>`.
Then call `tao::pegtl::analyze()` with the top-level grammar rule as template argument.

```c++
#include <tao/pegtl/analyze.hpp>

const std::size_t issues_found = tao::pegtl::analyze< my_grammar >();
```

The `analyze()`-function returns the number of issues found and writes some information about them to `std::cout`.

Analysing a grammar is usually only done while developing and debugging a grammar, or after changing it.

Regarding the kinds of issues that are detected, consider the following example grammar rules.

```c++
struct bar;

struct foo
   : sor< digit, bar > {};

struct bar
   : plus< foo > {};
```

When attempting to match `bar` against an input where the next character is not a digit the parser immediately goes into an infinite loop between `bar` calling `foo` and then `foo` calling `bar` again.

As shown by the example program `src/example/pegtl/analyze.cpp`, the grammar analysis will correctly detect a cycle without progress in this grammar.

Due to the differences regarding back-tracking and non-deterministic behaviour, this kind of infinite loop is a frequent issue when translating a CFG into a PEG.

## Background

In order to look for infinite loops in a grammar, the `analyze()`-function needs some information about all rules in the grammar.
This "information" consists of a classification of the rules according to the following enum, plus, for non-atomic rules, a list of the sub-rules.

```c++
// namespace tao::pegtl::analysis

enum class rule_type : char
{
   ANY,
   OPT,
   SEQ,
   SOR
};
```

This enum value and rule list are provided to the `analyze()`-function via an `analyze_t` type member that all rules that are part of a grammar that is to be analysed with `analyze()` need to define.

The names of the enum values correspond to one of the PEGTL rule classes that has this rule type, however some rule types are used by many different classes.

* `ANY` is for rules where "success implies consumption" is true; assumes bounded repetition of conjunction of sub-rules.
* `OPT` is for rules where "success implies consumption" is false; assumes bounded repetition of conjunction of sub-rules.
* `SEQ` is for rules where consumption on success depends on non-zero bounded repetition of the conjunction of sub-rules.
* `SOR` is for rules where consumption on success depends on non-zero bounded repetition of the disjunction of sub-rules.

At the beginning of an `analyze()`-run the function `R::analyze_t::insert()` is called for all rules `R` in the grammar in order to insert the information about the rule `R` into a data structure.

## Custom Rules

For custom rules it should usually be sufficient to follow the lead of the rules supplied with the PEGTL and define `analyze_t` to either `tao::pegtl::analysis::generic` or `tao::pegtl::analysis::counted`.
In both cases, the `rule_type` and the list of sub-rules must be supplied as template parameters.
Class `tao::pegtl::analysis::counted` additionally takes an integer argument `Count` with the assumption being that a count of zero indicates that everything the rule type is `OPT` while a non-zero count uses the rule type given as template parameter.

When a custom rule goes beyond what can be currently expressed and all other questions, please contact the authors at **taocpp(at)icemx.net**.

Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
