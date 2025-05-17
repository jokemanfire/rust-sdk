#[allow(unused_imports)]
use proc_macro::TokenStream;

mod tool;
mod tool_extend;

#[proc_macro_attribute]
pub fn tool(attr: TokenStream, input: TokenStream) -> TokenStream {
    tool::tool(attr.into(), input.into())
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

#[proc_macro_attribute]
pub fn tool_extend(attr: TokenStream, input: TokenStream) -> TokenStream {
    tool_extend::tool_extend(attr.into(), input.into())
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}
