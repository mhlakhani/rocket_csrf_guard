#![warn(clippy::all, clippy::pedantic, clippy::nursery)]

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::parse::{Parse, ParseStream, Parser, Result};
use syn::{
    parse_macro_input, punctuated::Punctuated, Error, Field, Fields, GenericParam, Ident,
    ItemStruct, LitStr, Token, Type,
};

#[derive(Debug)]
struct MaybeName {
    name: Option<LitStr>,
}

impl Parse for MaybeName {
    fn parse(input: ParseStream) -> Result<Self> {
        let vars = Punctuated::<syn::LitStr, Token![,]>::parse_terminated(input)?;
        if vars.is_empty() {
            Ok(Self { name: None })
        } else if vars.len() == 1 {
            Ok(Self {
                name: vars.first().cloned(),
            })
        } else {
            Err(Error::new(
                input.span(),
                "expected at most one field name for csrf token, got multiple!",
            ))
        }
    }
}

fn get_singular_lifetime(item: &ItemStruct) -> Option<Ident> {
    let generics = &item.generics;
    if generics.params.len() != 1 {
        return None;
    }
    if let Some(GenericParam::Lifetime(lifetime)) = generics.params.first() {
        Some(lifetime.lifetime.ident.clone())
    } else {
        None
    }
}

#[proc_macro_attribute]
pub fn with_csrf_token(args: TokenStream, input: TokenStream) -> TokenStream {
    let mut item_struct = parse_macro_input!(input as ItemStruct);
    let struct_name = item_struct.ident.clone();
    let maybe_names = parse_macro_input!(args as MaybeName);

    let field_name = maybe_names
        .name
        .map_or_else(|| "csrf_token".to_owned(), |s| s.value());

    let lifetime = get_singular_lifetime(&item_struct);
    let ident = Ident::new(&field_name, Span::call_site());

    if let Fields::Named(ref mut fields) = item_struct.fields {
        let existing = fields
            .named
            .iter()
            .any(|f| f.ident.as_ref().map_or(false, |i| *i == ident));
        // TODO: Validate field type is string or &str
        if !existing {
            if let Some(lifetime) = lifetime {
                if let Ok(mut field) = Field::parse_named.parse2(quote! { #ident: &'a str }) {
                    if let Type::Reference(reference) = &mut field.ty {
                        if let Some(field_lifetime) = reference.lifetime.as_mut() {
                            field_lifetime.ident = lifetime;
                        }
                    }
                    fields.named.push(field);
                }
            } else if let Ok(field) = syn::Field::parse_named.parse2(quote! { #ident: String }) {
                fields.named.push(field);
            }
        }
    }

    let (impl_generics, ty_generics, _) = item_struct.generics.split_for_impl();

    quote! {
        #item_struct

        impl #impl_generics rocket_csrf_guard::WithUserProvidedCsrfToken for #struct_name #ty_generics {
            fn csrf_token(&self) -> &str {
                &self.#ident
            }
        }
    }
    .into()
}
