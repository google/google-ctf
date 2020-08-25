# Errors and Exceptions

A parsing run, a call to one of the `parse()`-functions as explained in [Inputs and Parsing](Inputs-and-Parsing.md), can have the same results as calling the `match()`-method on a grammar rule.

* A return value of `true` indicates a *successful* match.
* A return value of `false` is called a *local failure* (even when propagated to the top).
* An exception indicating a *global failure* is thrown.

The PEGTL parsing rules throw exceptions of type `tao::pegtl::parse_error`, some of the inputs throw exceptions of type `tao::pegtl::input_error`.
Other exception classes can be used freely from actions and custom parsing rules.

## Contents

* [Local to Global Failure](#local-to-global-failure)
* [Global to Local Failure](#global-to-local-failure)
* [Examples for Must Rules](#examples-for-must-rules)
* [Custom Exception Messages](#custom-exception-messages)

## Local to Global Failure

A local failure returned by a parsing rule is not necessarily propagated to the top, for example when the rule is

* in a rule like `not_at<>`, `opt<>` or `star<>`, or
* not the last rule inside an `sor<>` combinator.

To convert local failures to global failures, the `must<>` combinator rule can be used (together with related rules like `if_must<>`, `if_must_else<>` and `star_must<>`).
The `must<>` rule is equivalent to `seq<>` in that it attempts to match all sub-rules in sequence, but converts all local failures of the (direct) sub-rules to global failures.

Global failures can also be unconditionally provoked with the `raise<>` grammar rule, which is more flexible since the template argument can be any type, not just a parsing rule.
It should be mentioned that `must< R >` is semantically equivalent to `sor< R, raise< R > >`, but more efficient.

In any case, the task of actually throwing an exception is delegated to the [control class'](Control-and-Debug.md) `raise()`-method.

## Global to Local Failure

To convert global failure to local failure, the grammar rules [`try_catch`](Rule-Reference.md#try_catch-r-) and [`try_catch_type`](Rule-Reference.md#try_catch_type-e-r-) can be used.
Since these rules are not very commonplace they are ignored in this document, in other words we assume that global failure always propagages to the top.

## Examples for Must Rules

One basic use case of the `must<>` rule is as top-level grammar rule.
Then a parsing run can only either be successful, or throw an exception, it is not necessary to check the return value of the `parse()` function.

For another use case consider the following parsing rules for a simplified C-string literal that only allows `\n`, `\r` and `\t` as escape sequences.
The rule `escaped` is for a single escaped character, the rule `content` is for the complete content of such a literal.

```c++
   using namespace tao::pegtl;
   struct escaped : seq< one< '\\' >, one< 'n', 'r', 't' > > {};
   struct content : star< sor< escaped, not_one< '\\', '"' > > > {};
   struct literal : seq< one< '"' >, content, one< '"' > > {};
```

The `escaped` rule first matches a backslash, and then one of the allowed subsequent characters.
When either of the two `one<>` rules returns a local failure, then so will `escaped` itself.
In that case backtracking is performed in the `sor<>` and it will attempt to match the `not_one< '\\', '"' >` at the same input position.

This backtracking is appropriate if the `escaped` rule failed to match for lack of a backslash in the input.
It is however *not* appropriate when the backslash was not followed by one of the allowed characters since we know that there is no other possibility that will lead to a successful match.

We can therefore re-write the `escaped` rule as follows so that once the backslash has matched we need one of the following allowed characters to match, otherwise a global failure is thrown.

```c++
   using namespace tao::pegtl;
   struct escaped : seq< one< '\\' >, must< one< 'n', 'r', 't' > > > {};
```

A `seq<>` where all but the first sub-rule is inside a `must<>` occurs frequently enough to merit a convenience rule.
The following rule is equivalent to the above.

```c++
   using namespace tao::pegtl;
   struct escaped : if_must< one< '\\' >, one< 'n', 'r', 't' > > {};
```

Now the `escaped` rule can only return local failure when the next input byte is not a backslash.
This knowledge can be used to simplify the `content` rule by not needing to exclude the backslash in the following rule.

```c++
   using namespace tao::pegtl;
   struct content : star< sor< escaped, not_one< '"' > > > {};
```

Finally we apply our "best practice" and give the `one< 'n', 'r', 't' >` rule a dedicated name.
This will improve the built-in error message when the global failure is thrown, and also prevents actions or custom error messages (as explained below) from accidentally attaching to the same rule used in multiple places in a grammar.
The resulting example is as follows.

```c++
   using namespace tao::pegtl;
   struct escchar : one< 'n', 'r', 't' > {};
   struct escaped : if_must< one< '\\' >, escchar > {};
   struct content : star< sor< escaped, not_one< '"' > > > {};
   struct literal : seq< one< '"' >, content, one< '"' > > {};
```

The same use of `if_must<>` can be applied to the `literal` rule assuming that it occurs in some `sor<>` where it is the only rule whose matched input can begin with a quotation mark...

## Custom Exception Messages

By default, when using any `must<>` error points, the exceptions generated by the PEGTL use the demangled name of the failed parsing rule as descriptive part of the error message. This is often insufficient and one would like to provide more meaningful error messages.

A practical technique to provide customised error message for all `must<>` error points uses a custom control class whose `raise()`-method uses a static string as error message.

```c++
template< typename Rule >
struct my_control
   : tao::pegtl::normal< Rule >
{
   static const std::string error_message;

   template< typename Input, typename... States >
   static void raise( const Input& in, States&&... )
   {
      throw tao::pegtl::parse_error( error_message, in );
   }
};
```

Now only the `error_message` string needs to be specialised per error point as follows.

```c++
template<> const std::string my_control< MyRule >::error_message = "expected ...";
```

Since the `raise()`-method is only instantiated for those rules for which `must<>` could trigger an exception, it is sufficient to provide specialisations of the error message string for those rules.
Furthermore, there will be a linker error for all rules for which the specialisation was forgotten although `raise()` could be called.
For an example of this method see `src/examples/pegtl/json_errors.hpp`, where all errors that might occur in the supplied JSON grammar are customised like this:

```c++
template<> const std::string errors< tao::pegtl::json::text >::error_message = "no valid JSON";

template<> const std::string errors< tao::pegtl::json::end_array >::error_message = "incomplete array, expected ']'";
template<> const std::string errors< tao::pegtl::json::end_object >::error_message = "incomplete object, expected '}'";
template<> const std::string errors< tao::pegtl::json::member >::error_message = "expected member";
template<> const std::string errors< tao::pegtl::json::name_separator >::error_message = "expected ':'";
template<> const std::string errors< tao::pegtl::json::array_element >::error_message = "expected value";
template<> const std::string errors< tao::pegtl::json::value >::error_message = "expected value";

template<> const std::string errors< tao::pegtl::json::digits >::error_message = "expected at least one digit";
template<> const std::string errors< tao::pegtl::json::xdigit >::error_message = "incomplete universal character name";
template<> const std::string errors< tao::pegtl::json::escaped >::error_message = "unknown escape sequence";
template<> const std::string errors< tao::pegtl::json::char_ >::error_message = "invalid character in string";
template<> const std::string errors< tao::pegtl::json::string::content >::error_message = "unterminated string";
template<> const std::string errors< tao::pegtl::json::key::content >::error_message = "unterminated key";

template<> const std::string errors< tao::pegtl::eof >::error_message = "unexpected character after JSON value";
```

It is also possible to provide a default error message that will be chosen by the compiler in the absence of a specialised one as follows.

```c++
template< typename T >
const std::string my_control< T >::error_message =
   "parse error matching " + tao::pegtl::internal::demangle< T >();
```

This is similar to the default behaviour, but one will not get a linker error in case as error point is missed.

It is advisable to choose the error points in the grammar with prudence.
This choice becoming particularly cumbersome and/or resulting in a large number of error points might be an indication of the grammar needing some kind of simplification or restructuring.

Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
