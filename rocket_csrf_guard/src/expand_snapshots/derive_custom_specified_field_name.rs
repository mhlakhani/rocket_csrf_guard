#![feature(prelude_import)]
#![allow(unused)]
#[prelude_import]
use std::prelude::rust_2021::*;
#[macro_use]
extern crate std;
use rocket_csrf_guard_derive::with_csrf_token;
/// You can change the name of the field you're using, even
/// if you specify it
struct SomeFormWithCustomSpecifiedName<'a> {
    name: &'a str,
    my_csrf_token: String,
}
impl<'a> rocket_csrf_guard::WithUserProvidedCsrfToken
for SomeFormWithCustomSpecifiedName<'a> {
    fn csrf_token(&self) -> &str {
        &self.my_csrf_token
    }
}
fn main() {}
