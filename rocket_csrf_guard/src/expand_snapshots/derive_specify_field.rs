#![feature(prelude_import)]
#![allow(unused)]
#[prelude_import]
use std::prelude::rust_2021::*;
#[macro_use]
extern crate std;
use rocket_csrf_guard_derive::with_csrf_token;
/// You can specify the field directly to fix it
struct SomeStructWithSpecifiedField<'a, 'b> {
    name: &'a str,
    csrf_token: &'b str,
}
impl<'a, 'b> rocket_csrf_guard::WithUserProvidedCsrfToken
for SomeStructWithSpecifiedField<'a, 'b> {
    fn csrf_token(&self) -> &str {
        &self.csrf_token
    }
}
fn main() {}
