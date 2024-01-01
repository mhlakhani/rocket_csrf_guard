#![allow(unused)]

use rocket_csrf_guard_derive::with_csrf_token;

/// You can specify the field directly to fix it
#[with_csrf_token]
struct SomeStructWithSpecifiedField<'a, 'b> {
    name: &'a str,
    csrf_token: &'b str,
}

fn main() {}
