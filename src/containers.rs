use std::rc::Rc;
use std::sync::Arc;

use crate::ast::{Literal, SpannedNode, TypeName, Value};
use crate::decode::Context;
use crate::errors::DecodeError;
use crate::span::Spanned;
use crate::traits::{Decode, DecodeChildren, DecodePartial, DecodeScalar, DecodeSpan};

impl<T: Decode> Decode for Box<T> {
    fn decode_node(node: &SpannedNode, ctx: &mut Context) -> Result<Self, DecodeError> {
        Decode::decode_node(node, ctx).map(Box::new)
    }
}

impl<T: DecodeChildren> DecodeChildren for Box<T> {
    fn decode_children(nodes: &[SpannedNode], ctx: &mut Context) -> Result<Self, DecodeError> {
        DecodeChildren::decode_children(nodes, ctx).map(Box::new)
    }
}

impl<T: DecodePartial> DecodePartial for Box<T> {
    fn insert_child(&mut self, node: &SpannedNode, ctx: &mut Context) -> Result<bool, DecodeError> {
        (**self).insert_child(node, ctx)
    }
    fn insert_property(
        &mut self,
        name: &Spanned<Box<str>>,
        value: &Value,
        ctx: &mut Context,
    ) -> Result<bool, DecodeError> {
        (**self).insert_property(name, value, ctx)
    }
}

impl<T: DecodeScalar> DecodeScalar for Box<T> {
    fn type_check(type_name: &Option<Spanned<TypeName>>, ctx: &mut Context) {
        T::type_check(type_name, ctx)
    }
    fn raw_decode(value: &Spanned<Literal>, ctx: &mut Context) -> Result<Self, DecodeError> {
        DecodeScalar::raw_decode(value, ctx).map(Box::new)
    }
}

impl<T: Decode> Decode for Arc<T> {
    fn decode_node(node: &SpannedNode, ctx: &mut Context) -> Result<Self, DecodeError> {
        Decode::decode_node(node, ctx).map(Arc::new)
    }
}

impl<T: DecodeChildren> DecodeChildren for Arc<T> {
    fn decode_children(nodes: &[SpannedNode], ctx: &mut Context) -> Result<Self, DecodeError> {
        DecodeChildren::decode_children(nodes, ctx).map(Arc::new)
    }
}

impl<T: DecodePartial> DecodePartial for Arc<T> {
    fn insert_child(&mut self, node: &SpannedNode, ctx: &mut Context) -> Result<bool, DecodeError> {
        Arc::get_mut(self)
            .expect("no Arc clone yet")
            .insert_child(node, ctx)
    }
    fn insert_property(
        &mut self,
        name: &Spanned<Box<str>>,
        value: &Value,
        ctx: &mut Context,
    ) -> Result<bool, DecodeError> {
        Arc::get_mut(self)
            .expect("no Arc clone yet")
            .insert_property(name, value, ctx)
    }
}

impl<T: DecodeScalar> DecodeScalar for Arc<T> {
    fn type_check(type_name: &Option<Spanned<TypeName>>, ctx: &mut Context) {
        T::type_check(type_name, ctx)
    }
    fn raw_decode(value: &Spanned<Literal>, ctx: &mut Context) -> Result<Self, DecodeError> {
        DecodeScalar::raw_decode(value, ctx).map(Arc::new)
    }
}

impl<T: Decode> Decode for Rc<T> {
    fn decode_node(node: &SpannedNode, ctx: &mut Context) -> Result<Self, DecodeError> {
        Decode::decode_node(node, ctx).map(Rc::new)
    }
}

impl<T: DecodeChildren> DecodeChildren for Rc<T> {
    fn decode_children(nodes: &[SpannedNode], ctx: &mut Context) -> Result<Self, DecodeError> {
        DecodeChildren::decode_children(nodes, ctx).map(Rc::new)
    }
}

impl<T: DecodePartial> DecodePartial for Rc<T> {
    fn insert_child(&mut self, node: &SpannedNode, ctx: &mut Context) -> Result<bool, DecodeError> {
        Rc::get_mut(self)
            .expect("no Rc clone yet")
            .insert_child(node, ctx)
    }
    fn insert_property(
        &mut self,
        name: &Spanned<Box<str>>,
        value: &Value,
        ctx: &mut Context,
    ) -> Result<bool, DecodeError> {
        Rc::get_mut(self)
            .expect("no Rc clone yet")
            .insert_property(name, value, ctx)
    }
}

impl<T: DecodeScalar> DecodeScalar for Rc<T> {
    fn type_check(type_name: &Option<Spanned<TypeName>>, ctx: &mut Context) {
        T::type_check(type_name, ctx)
    }
    fn raw_decode(value: &Spanned<Literal>, ctx: &mut Context) -> Result<Self, DecodeError> {
        DecodeScalar::raw_decode(value, ctx).map(Rc::new)
    }
}

impl<T: Decode> DecodeChildren for Vec<T> {
    fn decode_children(nodes: &[SpannedNode], ctx: &mut Context) -> Result<Self, DecodeError> {
        let mut result = Vec::with_capacity(nodes.len());
        for node in nodes {
            match Decode::decode_node(node, ctx) {
                Ok(node) => result.push(node),
                Err(e) => ctx.emit_error(e),
            }
        }
        Ok(result)
    }
}

impl<T: DecodeScalar> DecodeScalar for Option<T> {
    fn type_check(type_name: &Option<Spanned<TypeName>>, ctx: &mut Context) {
        T::type_check(type_name, ctx)
    }
    fn raw_decode(value: &Spanned<Literal>, ctx: &mut Context) -> Result<Self, DecodeError> {
        match &**value {
            Literal::Null => Ok(None),
            _ => DecodeScalar::raw_decode(value, ctx).map(Some),
        }
    }
}

impl<T: DecodeScalar> DecodeScalar for Spanned<T> {
    fn type_check(type_name: &Option<Spanned<TypeName>>, ctx: &mut Context) {
        T::type_check(type_name, ctx)
    }
    fn raw_decode(value: &Spanned<Literal>, ctx: &mut Context) -> Result<Self, DecodeError> {
        let decoded = T::raw_decode(value, ctx)?;
        Ok(Spanned {
            span: DecodeSpan::decode_span(&value.span, ctx),
            value: decoded,
        })
    }
}
