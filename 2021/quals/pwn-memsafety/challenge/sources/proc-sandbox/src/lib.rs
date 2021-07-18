/*
    Copyright 2021 Google LLC

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        https://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/
use proc_macro::TokenStream;
use quote::ToTokens;
use syn::visit::Visit;
use syn::{parse_macro_input, ExprUnsafe, ForeignItem, Ident, Item, ItemExternCrate};

struct Sandbox;
const BLOCKLIST: &[&str] = &[
    "env",
    "file",
    "include",
    "include_bytes",
    "include_str",
    "option_env",
    "std",
];

impl<'ast> Visit<'ast> for Sandbox {
    fn visit_expr_unsafe(&mut self, _: &'ast ExprUnsafe) {
        panic!("Unsafe is not allowed");
    }
    fn visit_foreign_item(&mut self, _: &'ast ForeignItem) {
        panic!("Linking to external symbols is not allowed");
    }
    fn visit_item_extern_crate(&mut self, _: &'ast ItemExternCrate) {
        panic!("Extern declarations are not allowed");
    }
    fn visit_ident(&mut self, ident: &'ast Ident) {
        // We could loosen this to only direct macro usage or use-rebinding
        if BLOCKLIST.iter().any(|blocked_ident| ident == blocked_ident) {
            panic!("Please don't try to access the compilation environment");
        }
    }
}

fn sandbox_item(item: Item) -> Item {
    Sandbox.visit_item(&item);
    item
}

#[proc_macro_attribute]
pub fn sandbox(_attr: TokenStream, item_tokens: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item_tokens as Item);
    TokenStream::from(sandbox_item(item).into_token_stream())
}
