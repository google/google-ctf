# Actions and States

Parsing, i.e. matching an input with a grammar rule, by itself only indicates whether (a portion of) the input is valid according to the grammar.
In order to do something useful with the input, it is usually necessary to attach user-defined *actions* to one or more rules.
An action is *applied* whenever the rule to which it is attached succeeds.
Applying an action means that its static `apply()` or `apply0()`-method is called.
The first argument to an `apply()` method is always an object that represents the portion of the input consumed by the successful match of the rule.
An action's `apply()` or `apply0()`-method can either return `void`, or a `bool`.

## Contents

* [Actions](#actions)
  * [Apply0](#apply0)
  * [Apply](#apply)
* [States](#states)
* [Action Specialisation](#action-specialisation)
* [Changing Actions](#changing-actions)
* [Changing State](#changing-state)
  * [No Switching](#no-switching)
  * [Intrusive Switching](#intrusive-switching)
  * [External Switching](#external-switching)
* [Legacy Actions](#legacy-actions)

## Actions

Actions are implemented as static `apply()` or `apply0()`-method of specialisations of custom class templates (which is not quite as difficult as it sounds).
First the default- or base-case of the action class template has to be defined:

```c++
template< typename Rule >
struct my_actions
   : tao::pegtl::nothing< Rule > {};
```

Inheriting from `tao::pegtl::nothing< Rule >` indicates to the PEGTL that no action is attached to `Rule`, i.e. that no `apply()` or `apply0()`-method should be called for successful matches of `Rule`.

To attach an action to `Rule`, this class template has to be specialised for `Rule` with two important properties.

1. The specialisation *must not* inherit from `tao::pegtl::nothing< Rule >`.

2. An *appropriate* static `apply()` or `apply0()`-method has to be implemented.

The PEGTL will auto-detect whether an action, i.e. a specialisation of an action class template, contains an appropriate `apply()` or `apply0()` function, and whether it returns `void` or `bool`.
It will fail to compile when both `apply()` and `apply0()` are found.

### Apply0

In cases where the matched part of the input is not required, an action method named `apply0()` is implemented.
This allows for some optimisations compared to the `apply()` method which receives the matched input as first argument.

```c++
template<>
struct my_actions< tao::pegtl::plus< tao::pegtl::alpha > >
{
   static void apply0( /* all the states */ )
   {
      // Called whenever a call to tao::pegtl::plus< tao::pegtl::alpha >
      // in the grammar succeeds.
   }

   // OR ALTERNATIVELY

   static bool apply0( /* all the states */ )
   {
      // Called whenever a call to tao::pegtl::plus< tao::pegtl::alpha >
      // in the grammar succeeds.
      return // see below
   }
}
```

When the return type is `bool`, the action can determine whether matching the rule to which it was attached, and which already returned with success, should be retro-actively considered a (local) failure.
For the overall parsing run, there is no difference between a rule or an attached action returning `false` (but of course the action is not called when the rule already returned `false`).
When an action returns `false`, the PEGTL takes care of rewinding the input to where it was when the rule to which the action was attached started its (successful) match (which is unlike rules' `match()` methods that have to take care of rewinding themselves).

Note that actions returning `bool` are an advanced use case that should be used with caution.
They prevent some internal optimisations, in particular when used with `apply0()`.
They can also have weird effects on the semantics of a parsing run, for example `at< rule >` can succeed for the same input for which `rule` fails when there is a `bool`-action attached to `rule` that returns `false` (remembering that actions are disabled within an `at<>` combinator).

### Apply

When the action method is called `apply()`, it receives a const-reference to an instance of an input class as first argument.

```c++
template<>
struct my_actions< tao::pegtl::plus< tao::pegtl::digit > >
{
   template< typename Input >
   static void apply( const Input& in, /* all the states */ )
   {
      // Called whenever a call to tao::pegtl::plus< tao::pegtl::digit >
      // in the grammar succeeds. The argument named 'in' represents the
      // matched part of the input.
   }

   // OR ALTERNATIVELY

   template< typename Input >
   static bool apply( const Input& in, /* all the states */ )
   {
      // Called whenever a call to tao::pegtl::plus< tao::pegtl::digit >
      // in the grammar succeeds. The argument named 'in' represents the
      // matched part of the input.
      return // see description for apply0() above
   }
}
```

The exact type of the input class passed to an action's `apply()`-method is not specified.
It is currently best practice to "template over" the type of the input as shown above.

Actions can then assume that the input provides (at least) the following members.
The `Input` template parameter is set to the class of the input used at the point in the parsing run where the action is applied.

For illustrative purposes, we will assume that the input passed to `apply()` is of type `action_input`.
Any resemblance to real classes is not a coincidence.

```c++
template< typename Input >
class action_input
{
public:
   using input_t = Input;
   using iterator_t = typename Input::iterator_t;

   bool empty() const noexcept;
   std::size_t size() const noexcept;

   const char* begin() const noexcept;  // Non-owning pointer!
   const char* end() const noexcept;  // Non-owning pointer!

   std::string string() const;  // { return std::string( begin(), end() ); }

   char peek_char( const std::size_t offset = 0 ) const noexcept;   // { return begin()[ offset ]; }
   unsigned char peek_byte( const std::size_t offset = 0 ) const noexcept;  // As above with cast.

   pegtl::position position() const noexcept;  // Not efficient with LAZY inputs.

   const Input& input() const noexcept;  // The input from the parsing run.

   const iterator_t& iterator() const noexcept;
};
```

Note that the `action_input` does **not** own the data it points to, it belongs to the original input used in the parsing run. Therefore **the validity of the pointed-to data might not extend (much) beyond the call to the `apply()`-method**!

When the original input has tracking mode `IMMEDIATE`, the `iterator_t` returned by `action_input::iterator()` will contain the `byte`, `line` and `byte_in_line` counters corresponding to the beginning of the matched input represented by the `action_input`.

When the original input has tracking mode `LAZY`, then `action_input::position()` is not efficient because it calculates the line number etc. by scanning the complete original input from the beginning.

Actions often need to store and/or reference portions of the input for after the parsing run, for example when an abstract syntax tree is generated.
Some of the syntax tree nodes will contain portions of the input, for example for a variable name in a script language that needs to be stored in the syntax tree just as it occurs in the input data.

The **default safe choice** is to copy the matched portions of the input data that are passed to an action by storing a deep copy of the data as `std::string`, as obtained by the input class' `string()` method, in the data structures built while parsing.

## States

In most applications, the actions also need some kind of data or user-defined (parser/action) *state* to operate on.
Since the `apply()` and `apply0()`-methods are `static`, they do not have an instance of the class of which they are a member function available for this purpose.
Therefore the *state(s)* are an arbitrary collection of objects that are

* passed by the user as additional arguments to the [`parse()`-function](Inputs-and-Parsing.md#parse-function) that starts a parsing run, and then

* passed by the PEGTL as additional arguments to all actions' `apply()` or `apply0()`-method.

In other words, the additional arguments to the `apply()` and `apply0()`-method can be chosen freely, however **all** actions **must** accept the same argument list since they are **all** called with the same arguments.

For example, in a practical grammar the example from above might use a second argument to store the parsed sequence of digits somewhere.

```c++
template<> struct my_actions< tao::pegtl::plus< tao::pegtl::digit > >
{
   template< typename Input >
   static void apply( const Input& in,
                      std::vector< std::string >& digit_strings )
   {
      digit_strings.push_back( in.string() );
   }
}
```

If we then assume that our grammar `my_grammar` contains the rule `tao::pegtl::plus< tao::pegtl::digit >` somewhere, we can use

```c++
const std::string parsed_data = ...;
std::vector< std::string > digit_strings;

tao::pegtl::memory_input<> in( parsed_data, "data-source-name" );
tao::pegtl::parse< my_grammar, my_actions >( in, digit_strings );
```

to collect all `digit_strings` that were detected by the grammar, i.e. the vector will contain one string for every time that the `tao::pegtl::plus< tao::pegtl::digit >` rule was matched against the input.

Since the `parse()`-functions are variadic function templates, an arbitrary sequence of state arguments can be used.

## Action Specialisation

The rule class for which the action class template is specialised *must* exactly match how the rule is defined and referenced in the grammar.
For example given the rule

```c++
struct foo : tao::pegtl::plus< tao::pegtl::one< '*' > > {};
```

an action class template can be specialised for `foo` or for `tao::pegtl::one< '*' >`, but *not* for `tao::pegtl::plus< tao::pegtl::one< '*' > >` because that is not the rule class name whose `match()`-method is called.

(The method is called on class `foo`, which happens to inherit `match()` from `tao::pegtl::plus< tao::pegtl::one< '*' > >`, however base classes are not taken into consideration by the C++ language when choosing a specialisation.)

While it is possible to specialize for `tao::pegtl::one< '*' >` in the above rule, any such specialization would also match any other occurrence in the grammar. It is therefore best practice to *always* specialize for explicitly named top-level rules.

To then use these actions in a parsing run, simply pass them as additional template parameter to one of the parser functions defined in `<tao/pegtl/parse.hpp>`.

```c++
tao::pegtl::parse< my_grammar, my_actions >( ... );
```

## Changing Actions

Within a grammar, the action class template can be changed, enabled or disabled using the `action<>`, `enable<>` and `disable<>` rules.

The following two lines effectively do the same thing, namely parse with `my_grammar` as top-level parsing rule without invoking actions (unless actions are enabled again somewhere within the grammar).

```c++
tao::pegtl::parse< my_grammar >( ... );
tao::pegtl::parse< tao::pegtl::disable< my_grammar >, my_actions >( ... );
```

Similarly the following two lines both start parsing `my_grammar` with `my_actions` (again with the caveat that something might change somewhere in the grammar).

```c++
tao::pegtl::parse< my_grammar, my_actions >( ... );
tao::pegtl::parse< tao::pegtl::action< my_actions, my_grammar > >( ... );
```

In other words, `enable<>` and `disable<>` behave just like `seq<>` but enable or disable the calling of actions. `action<>` changes the active action class template, which must be supplied as first template parameter to `action<>`.

Note that `action<>` does *not* implicitly enable actions when they were previously explicitly disabled.

User-defined parsing rules can use `action<>`, `enable<>` and `disable<>` just like any other combinator rules, for example to disable actions in LISP-style comments:

```c++
struct comment
   : tao::pegtl::seq< tao::pegtl::one< '#' >, tao::pegtl::disable< cons_list > > {};
```

This also allows using the same rules multiple times with different actions within the grammar.

## Changing States

Implementing a parser with the PEGTL consists of two main parts.

1. The actual grammar that drives the parser.
2. The states and actions that "do something".

For the second part, there are three distinct styles of how to manage the states and actions in non-trivial parsers.

The **main issue** addressed by the switching styles is the **growing complexity** encountered when a single state argument to a parsing run must perform multiple different tasks, including the management of nested data structures.

The way that this issue is addressed is by providing another tool for performing divide-and-conquer: A large state class with multiple tasks can be divided into

- multiple smaller state classes that each take care of a single issue,
- one or more [control classes](Control-and-Debug.md) that switch between the states,
- using the C++ stack for nested structures (rather than manually managing a stack).

The different styles can also be freely mixed within the same parser.

### No Switching

The "no switching style" consists of having one (or more) state-arguments that are passed to a parsing run and that are the arguments to all action's `apply0()`- and `apply()`-methods.

For an example of how to build a generic JSON data structure with the "no switching style" see `src/example/pegtl/json_build_two.cpp`.

### Intrusive Switching

The `state<>` and `action<>` [meta combinators](Rule-Reference.md#meta-rules) can be used to hard-code state and actions switches in the grammar.

In some cases a state object is required for the grammar itself, and in these cases embedding the state-switch into the grammar is recommended.

### External Switching

"External switching" is when the states and/or actions are switched from outside of the grammar by providing a specialised control class.

For an example of how to build a generic JSON data structure with the "external switching style" see `src/example/pegtl/json_build_one.cpp`.

The actual switching control classes are defined in `<tao/pegtl/contrib/changes.hpp>` and can be used as template for custom switching.

## Legacy Actions

See the [section on legacy-style action rules](Rule-Reference.md#action-rules).

Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
