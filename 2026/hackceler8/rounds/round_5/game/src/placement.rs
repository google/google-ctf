// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the License);
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an AS IS BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! In-place ("placement") struct construction.
//!
//! The m68k codegen backend does not perform return-value optimisation: a
//! `fn new() -> BigStruct` materialises the whole struct in the *caller's* stack
//! frame and then copies it into its destination. On the 68000's 64KB RAM that
//! bloats frames until they collide with static `.data`/`.bss`. The [`emplace!`]
//! macro writes each field straight into its final home instead, so no by-value
//! temporary is ever built.

/// Write the fields of a struct directly into a caller-provided `*mut T`,
/// without ever building a by-value temporary, while keeping the full
/// compile-time field-exhaustiveness and type checking of a `T { .. }` literal.
///
/// ```ignore
/// emplace!(ptr, Self {
///     small_field: value,
///     other: compute(),
/// });
/// ```
///
/// Large nested fields are initialised in place by the *caller* (typically via
/// the field type's own `emplace`) and listed in an `init_elsewhere:` clause so
/// the exhaustiveness check still accounts for them but the macro doesn't write
/// (or move) them:
///
/// ```ignore
/// // caller initialised `(*ptr).map` itself, in place
/// emplace!(ptr, Self { /* the value fields ... */ } init_elsewhere: [map]);
/// ```
///
/// # Safety
/// `place` must point to writable, aligned, uninitialised memory for a `T`.
/// Each listed value field is written exactly once with no `Drop` of any prior
/// contents; fields named in `init_elsewhere` must have been initialised by the
/// caller before the resulting value is used.
macro_rules! emplace {
    ($place:expr, $Ty:path {
        $($name:ident : $val:expr),* $(,)?
    } $(init_elsewhere: [ $($ext:ident),* $(,)? ])? ) => {{
        let __place: *mut $Ty = $place;

        // Compile-time only: never executed and emits no code. The irrefutable
        // pattern (note: no `..`) forces every field of `$Ty` to be named
        // exactly once across the value fields and the `init_elsewhere` list —
        // the same guarantee a `$Ty { .. }` literal gives. Add/rename/remove a
        // field and forget it here => compile error, not silent UB.
        #[allow(unreachable_code, unused_variables, dead_code)]
        if false {
            let __t: $Ty = ::core::unreachable!();
            let $Ty { $($name: _,)* $($($ext: _,)*)? } = __t;
        }

        // Runtime: place each value field into its final address.
        #[allow(unused_unsafe)]
        unsafe {
            $(
                ::core::ptr::write(::core::ptr::addr_of_mut!((*__place).$name), $val);
            )*
        }
    }};
}

pub(crate) use emplace;
