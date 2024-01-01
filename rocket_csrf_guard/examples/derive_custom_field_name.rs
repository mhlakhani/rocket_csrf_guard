#![allow(unused)]

use rocket_csrf_guard_derive::with_csrf_token;

/// You can change the name of the field you'd like generated
#[with_csrf_token("my_csrf_token")]
struct SomeFormWithCustomName<'a> {
    name: &'a str,
}

fn main() {}
