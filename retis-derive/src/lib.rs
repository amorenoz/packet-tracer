use proc_macro::{self, TokenStream};
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

#[proc_macro_derive(EventSection)]
pub fn derive_event_section(input: TokenStream) -> TokenStream {
    let DeriveInput { ident, .. } = parse_macro_input!(input);
    let output = quote! {
        impl EventSectionInternal for #ident {
            fn as_any(&self) -> &dyn std::any::Any
                where Self: Sized,
            {
                self
            }

            fn to_json(&self) -> serde_json::Value
                where Self: serde::Serialize,
            {
                serde_json::json!(self)
            }
        }
    };
    output.into()
}

#[proc_macro_derive(EventSectionFactory)]
pub fn derive_event_section_factory(input: TokenStream) -> TokenStream {
    let input: DeriveInput = parse_macro_input!(input);
    let ident = &input.ident;

    let output = quote! {
        impl EventSectionFactory for #ident {
            fn as_any_mut(&mut self) -> &mut dyn std::any::Any
                where Self: Sized,
            {
                self
            }
        }
    };
    output.into()
}
