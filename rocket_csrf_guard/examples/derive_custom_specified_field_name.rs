#![allow(unused)]

use rocket_csrf_guard_derive::with_csrf_token;

/// You can change the name of the field you're using, even
/// if you specify it
#[with_csrf_token("my_csrf_token")]
struct SomeFormWithCustomSpecifiedName<'a> {
    name: &'a str,
    my_csrf_token: String,
}

fn main() {}
