use crate::ast::{Literal, Node, SpannedNode, TypeName, Value};
use crate::decode::Context;
use crate::errors::DecodeError;
use crate::span::Spanned;
use crate::traits::{Decode, DecodeScalar, DecodeSpan};

impl Decode for Node {
    fn decode_node(node: &SpannedNode, ctx: &mut Context) -> Result<Self, DecodeError> {
        Ok(Node {
            type_name: node.type_name.as_ref().map(|n| n.clone_as(ctx)),
            node_name: node.node_name.clone_as(ctx),
            arguments: node
                .arguments
                .iter()
                .map(|v| DecodeScalar::decode(v, ctx))
                .collect::<Result<_, _>>()?,
            properties: node
                .properties
                .iter()
                .map(|(k, v)| Ok((k.clone_as(ctx), DecodeScalar::decode(v, ctx)?)))
                .collect::<Result<_, _>>()?,
            children: node
                .children
                .as_ref()
                .map(|sc| {
                    Ok(Spanned {
                        span: DecodeSpan::decode_span(&sc.span, ctx),
                        value: sc
                            .iter()
                            .map(|node| {
                                Ok(Spanned {
                                    span: DecodeSpan::decode_span(&node.span, ctx),
                                    value: Decode::decode_node(node, ctx)?,
                                })
                            })
                            .collect::<Result<_, _>>()?,
                    })
                })
                .transpose()?,
        })
    }
}

impl Decode for SpannedNode {
    fn decode_node(node: &SpannedNode, ctx: &mut Context) -> Result<Self, DecodeError> {
        Ok(Spanned {
            span: DecodeSpan::decode_span(&node.span, ctx),
            value: Decode::decode_node(node, ctx)?,
        })
    }
}

impl DecodeScalar for Value {
    fn type_check(_type_name: &Option<Spanned<TypeName>>, _ctx: &mut Context) {}
    fn raw_decode(_value: &Spanned<Literal>, _ctx: &mut Context) -> Result<Self, DecodeError> {
        panic!("called `raw_decode` directly on the `Value`");
    }
    fn decode(value: &Value, ctx: &mut Context) -> Result<Self, DecodeError> {
        Ok(Value {
            type_name: value.type_name.as_ref().map(|n| n.clone_as(ctx)),
            literal: value.literal.clone_as(ctx),
        })
    }
}

impl DecodeScalar for Literal {
    fn type_check(_type_name: &Option<Spanned<TypeName>>, _ctx: &mut Context) {}
    fn raw_decode(value: &Spanned<Literal>, _ctx: &mut Context) -> Result<Self, DecodeError> {
        Ok((**value).clone())
    }
}
