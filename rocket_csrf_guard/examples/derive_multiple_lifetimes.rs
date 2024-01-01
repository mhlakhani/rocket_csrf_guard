#![allow(unused)]

use rocket_csrf_guard_derive::with_csrf_token;

/// If there are multiple lifetime parameters, fall back to a String
#[with_csrf_token]
struct SomeFormWithMultipleLifetimes<'a, 'b> {
    name: &'a str,
    something: &'b str,
}

fn main() {}
