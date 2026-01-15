use proc_macro2::{Span, TokenStream};
use quote::quote;

use crate::definition::{Enum, VariantKind};
use crate::node;

pub(crate) struct Common<'a> {
    pub object: &'a Enum,
    pub ctx: &'a syn::Ident,
}

pub fn emit_enum(e: &Enum) -> syn::Result<TokenStream> {
    let name = &e.ident;
    let node = syn::Ident::new("node", Span::mixed_site());
    let ctx = syn::Ident::new("ctx", Span::mixed_site());

    let (_, type_gen, _) = e.generics.split_for_impl();
    let mut common_generics = e.generics.clone();
    if common_generics.params.is_empty() {
        common_generics.lt_token = Some(Default::default());
        common_generics.gt_token = Some(Default::default());
    }
    let (impl_gen, _, bounds) = common_generics.split_for_impl();

    let common = Common {
        object: e,
        ctx: &ctx,
    };

    let decode = decode(&common, &node)?;
    Ok(quote! {
        impl #impl_gen ::knus::Decode for #name #type_gen
            #bounds
        {
            fn decode_node(#node: &::knus::ast::SpannedNode,
                           #ctx: &mut ::knus::decode::Context)
                -> ::std::result::Result<Self, ::knus::errors::DecodeError>
            {
                #decode
            }
        }
    })
}

fn decode(e: &Common, node: &syn::Ident) -> syn::Result<TokenStream> {
    let ctx = e.ctx;
    let mut branches = Vec::with_capacity(e.object.variants.len());
    let enum_name = &e.object.ident;
    for var in &e.object.variants {
        let name = &var.name;
        let variant_name = &var.ident;
        match &var.kind {
            VariantKind::Unit => {
                branches.push(quote! {
                    #name => {
                        for arg in &#node.arguments {
                            #ctx.emit_error(
                                ::knus::errors::DecodeError::unexpected(
                                    &arg.literal, "argument",
                                    "unexpected argument"));
                        }
                        for (name, _) in &#node.properties {
                            #ctx.emit_error(
                                ::knus::errors::DecodeError::unexpected(
                                    name, "property",
                                    format!("unexpected property `{}`",
                                            name.escape_default())));
                        }
                        if let Some(children) = &#node.children {
                            for child in children.iter() {
                                #ctx.emit_error(
                                    ::knus::errors::DecodeError::unexpected(
                                        child, "node",
                                        format!("unexpected node `{}`",
                                            child.node_name.escape_default())
                                    ));
                            }
                        }
                        Ok(#enum_name::#variant_name)
                    }
                });
            }
            VariantKind::Nested { option: false } => {
                branches.push(quote! {
                    #name => ::knus::Decode::decode_node(#node, #ctx)
                        .map(#enum_name::#variant_name),
                });
            }
            VariantKind::Nested { option: true } => {
                branches.push(quote! {
                    #name => {
                        if #node.arguments.len() > 0 ||
                            #node.properties.len() > 0 ||
                            #node.children.is_some()
                        {
                            ::knus::Decode::decode_node(#node, #ctx)
                                .map(Some)
                                .map(#enum_name::#variant_name)
                        } else {
                            Ok(#enum_name::#variant_name(None))
                        }
                    }
                });
            }
            VariantKind::Tuple(s) => {
                let common = node::Common { object: s, ctx };
                let decode = node::decode_enum_item(
                    &common,
                    quote!(#enum_name::#variant_name),
                    node,
                    false,
                )?;
                branches.push(quote! {
                    #name => { #decode }
                });
            }
            VariantKind::Named(s) => {
                let common = node::Common { object: s, ctx };
                let decode =
                    node::decode_enum_item(&common, quote!(#enum_name::#variant_name), node, true)?;
                branches.push(quote! {
                    #name => { #decode }
                });
            }
        }
    }
    // TODO(tailhook) use strsim to find similar names
    let err = if e.object.variants.len() <= 3 {
        format!(
            "expected one of {}",
            e.object
                .variants
                .iter()
                .map(|v| format!("`{}`", v.name.escape_default()))
                .collect::<Vec<_>>()
                .join(", ")
        )
    } else {
        format!(
            "expected `{}`, `{}`, or one of {} others",
            e.object.variants[0].name.escape_default(),
            e.object.variants[1].name.escape_default(),
            e.object.variants.len() - 2
        )
    };
    Ok(quote! {
        match &**#node.node_name {
            #(#branches)*
            name_str => {
                Err(::knus::errors::DecodeError::conversion(
                        &#node.node_name, #err))
            }
        }
    })
}
