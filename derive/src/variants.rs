use proc_macro2::{Span, TokenStream};
use quote::quote;

use crate::definition::{Enum, VariantKind};
use crate::node;

pub(crate) struct Common<'a> {
    pub object: &'a Enum,
    pub ctx: &'a syn::Ident,
    pub span_type: &'a TokenStream,
}

pub fn emit_enum(e: &Enum) -> syn::Result<TokenStream> {
    let name = &e.ident;
    let node = syn::Ident::new("node", Span::mixed_site());
    let ctx = syn::Ident::new("ctx", Span::mixed_site());

    let (_, type_gen, _) = e.generics.split_for_impl();
    let mut common_generics = e.generics.clone();
    let span_ty;
    if let Some(ty) = e.trait_props.span_type.as_ref() {
        span_ty = quote!(#ty);
    } else {
        if common_generics.params.is_empty() {
            common_generics.lt_token = Some(Default::default());
            common_generics.gt_token = Some(Default::default());
        }
        common_generics.params.push(syn::parse2(quote!(S)).unwrap());
        span_ty = quote!(S);
        common_generics
            .make_where_clause()
            .predicates
            .push(syn::parse2(quote!(S: ::knus::traits::ErrorSpan)).unwrap());
    };
    let trait_gen = quote!(<#span_ty>);
    let (impl_gen, _, bounds) = common_generics.split_for_impl();

    let common = Common {
        object: e,
        ctx: &ctx,
        span_type: &span_ty,
    };

    let decode = decode(&common, &node)?;
    Ok(quote! {
        impl #impl_gen ::knus::Decode #trait_gen for #name #type_gen
            #bounds
        {
            fn decode_node(#node: &::knus::ast::SpannedNode<#span_ty>,
                           #ctx: &mut ::knus::decode::Context<#span_ty>)
                -> ::std::result::Result<Self, ::knus::errors::DecodeError<#span_ty>>
            {
                #decode
            }
        }
    })
}

fn decode(e: &Common, node: &syn::Ident) -> syn::Result<TokenStream> {
    let ctx = e.ctx;
    let mut branches = Vec::with_capacity(e.object.variants.len());
    let mut transparent_variants = Vec::with_capacity(e.object.variants.len());
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
            VariantKind::Nested {
                option: None,
                transparent: false,
                ..
            } => {
                branches.push(quote! {
                    #name => ::knus::Decode::decode_node(#node, #ctx)
                        .map(#enum_name::#variant_name),
                });
            }
            VariantKind::Nested {
                option: None,
                transparent: true,
                inner_ty,
            } => {
                // Use the inner type to decode the input, then wrap it inside of the variant
                transparent_variants.push(quote! {
                   #inner_ty::decode_node(#node, #ctx).map(#enum_name::#variant_name)
                });
            }
            VariantKind::Nested {
                option: Some(inner_ty),
                transparent: true,
                ..
            } => {
                // Use the inner type (inside the option) to decode the input,
                transparent_variants.push(quote! {
                    {
                        if #node.arguments.len() > 0 ||
                            #node.properties.len() > 0 ||
                            #node.children.is_some()
                        {
                            #inner_ty::decode_node(#node, #ctx).map(Some).map(#enum_name::#variant_name)
                        } else {
                            Ok(#enum_name::#variant_name(None))
                        }
                    }
                });
            }
            VariantKind::Nested {
                option: Some(_),
                transparent: false,
                ..
            } => {
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
                let common = node::Common {
                    object: s,
                    ctx,
                    span_type: e.span_type,
                };
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
            VariantKind::Named => unimplemented!(),
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
        #(
            if let Ok(parsed) = #transparent_variants {
                Ok(parsed)
            } else
        )* {
            match &**#node.node_name {
                #(#branches)*
                name_str => {
                    Err(::knus::errors::DecodeError::conversion(
                            &#node.node_name, #err))
                }
            }
        }
    })
}
