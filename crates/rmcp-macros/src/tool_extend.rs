use std::collections::HashSet;

use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::{
    Expr, FnArg, Ident, ItemFn, ItemImpl, PatType, Token, Type, Visibility, parse::Parse,
    parse_quote, spanned::Spanned,
};

// 从tool.rs复用
const TOOL_IDENT: &str = "tool";


#[derive(Default)]
struct ToolExtendImplItemAttrs {
    tool_box: Option<Option<Ident>>,
}

impl Parse for ToolExtendImplItemAttrs {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let mut tool_box = None;
        while !input.is_empty() {
            let key: Ident = input.parse()?;
            match key.to_string().as_str() {
                "tool_box" => {
                    tool_box = Some(None);
                    if input.lookahead1().peek(Token![=]) {
                        input.parse::<Token![=]>()?;
                        let value: Ident = input.parse()?;
                        tool_box = Some(Some(value));
                    }
                }
                _ => {
                    return Err(syn::Error::new(key.span(), "unknown attribute"));
                }
            }
            if input.is_empty() {
                break;
            }
            input.parse::<Token![,]>()?;
        }

        Ok(ToolExtendImplItemAttrs { tool_box })
    }
}

pub enum ToolExtendItem {
    Impl(ItemImpl),
}

impl Parse for ToolExtendItem {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let lookahead = input.lookahead1();
        if lookahead.peek(Token![impl]) {
            let item = input.parse::<ItemImpl>()?;
            Ok(ToolExtendItem::Impl(item))
        } else {
            Err(syn::Error::new(
                input.span(),
                "tool_extend only supports impl blocks",
            ))
        }
    }
}

// 主入口函数
pub(crate) fn tool_extend(attr: TokenStream, input: TokenStream) -> syn::Result<TokenStream> {
    let tool_item = syn::parse2::<ToolExtendItem>(input)?;
    match tool_item {
        ToolExtendItem::Impl(item) => tool_extend_impl_item(attr, item),
    }
}

// 处理impl块
pub(crate) fn tool_extend_impl_item(attr: TokenStream, mut input: ItemImpl) -> syn::Result<TokenStream> {
    let tool_impl_attr: ToolExtendImplItemAttrs = syn::parse2(attr)?;
  
    // 获取工具箱名称
    let tool_box_ident = match tool_impl_attr.tool_box {
        Some(Some(ident)) => ident,
        _ => {
            return Err(syn::Error::new(
                proc_macro2::Span::call_site(),
                "tool_box attribute with name is required for tool_extend",
            ));
        }
    };

    // 获取所有标记为工具的函数标识符
    let mut tool_fn_idents = Vec::new();
    for item in &input.items {
        if let syn::ImplItem::Fn(method) = item {
            for attr in &method.attrs {
                if attr.path().is_ident(TOOL_IDENT) {
                    tool_fn_idents.push(method.sig.ident.clone());
                }
            }
        }
    }

    // 不支持trait实现
    if input.trait_.is_some() {
        return Err(syn::Error::new(
            proc_macro2::Span::call_site(),
            "tool_extend does not support trait implementations",
        ));
    }

    // 不支持泛型参数
    if !input.generics.params.is_empty() {
        return Err(syn::Error::new(
            proc_macro2::Span::call_site(),
            "tool_extend does not support generic parameters",
        ));
    }

    // 如果没有工具函数，直接返回
    if tool_fn_idents.is_empty() {
        return Ok(quote! { #input });
    }

    // 获取实现类型
    let self_ty = &input.self_ty;
    
    // 创建每个工具函数的匹配arm
    let match_arms = tool_fn_idents.iter().map(|ident| {
        let attr_fn = Ident::new(&format!("{}_tool_attr", ident), ident.span());
        let call_fn = Ident::new(&format!("{}_tool_call", ident), ident.span());
        quote! {
            name if name == Self::#attr_fn().name => {
                Self::#call_fn(tcc).await
            }
        }
    });
    
    // 创建工具属性列表
    let tool_attrs = tool_fn_idents.iter().map(|ident| {
        let attr_fn = Ident::new(&format!("{}_tool_attr", ident), ident.span());
        quote! { Self::#attr_fn() }
    });
    
    // 添加一个注册方法，用于将工具添加到工具箱
    // input.items.push(parse_quote! {
    //     #[doc(hidden)]
    //     fn __extend_tools() {
    //         static REGISTERED: std::sync::Once = std::sync::Once::new();
    //         REGISTERED.call_once(|| {
    //             #(
    //                 let tool_attr = Self::#tool_fn_idents _tool_attr();
    //                 let tool_fn = |ctx| Box::pin(Self::#tool_fn_idents _tool_call(ctx));
    //                 #tool_box_ident().add((tool_attr, tool_fn).into());
    //             )*
    //         });
    //     }
    // });
    
    // 添加call_tool方法
    input.items.push(parse_quote! {
        #[doc(hidden)]
        async fn call_extend_tool(
            &self,
            request: rmcp::model::CallToolRequestParam,
            context: rmcp::service::RequestContext<rmcp::RoleServer>,
        ) -> Result<rmcp::model::CallToolResult, rmcp::Error> {
            let tcc = rmcp::handler::server::tool::ToolCallContext::new(self, request, context);
            match tcc.name() {
                #(#match_arms,)*
                _ => Err(rmcp::Error::invalid_params("extended tool not found", None)),
            }
        }
    });
    
    // 添加list_tools方法
    input.items.push(parse_quote! {
        #[doc(hidden)]
        async fn list_extend_tools(
            &self,
            _: rmcp::model::PaginatedRequestParam,
            _: rmcp::service::RequestContext<rmcp::RoleServer>,
        ) -> Result<rmcp::model::ListToolsResult, rmcp::Error> {
            Ok(rmcp::model::ListToolsResult {
                next_cursor: None,
                tools: vec![#(#tool_attrs),*],
            })
        }
    });
    
    // 调用初始化函数
    input.items.push(parse_quote! {
        #[doc(hidden)]
        const _: () = {
            Self::__extend_tools();
        };
    });
    
    Ok(quote! {
        #input
    })
} 