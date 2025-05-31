use std::fmt;
use std::mem;

use proc_macro_error2::abort;
use proc_macro_error2::emit_error;
use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::GenericArgument;
use syn::PathArguments;
use syn::Type;
use syn::TypePath;
use syn::ext::IdentExt;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;

use crate::kw;

pub enum Definition {
    UnitStruct(Struct),
    TupleStruct(Struct),
    NewType(NewType),
    Struct(Struct),
    Enum(Enum),
}

#[allow(clippy::large_enum_variant)]
pub enum VariantKind {
    Unit,
    Nested {
        /// None: The type is not optional
        /// Some: Type is optional. Contains value inside the Option<...>
        option: Option<Type>,
        /// Delegate the entire parsing to the inner type
        transparent: bool,
        /// Type contained within
        inner_ty: TypePath,
    },
    Tuple(Struct),
    Named,
}

pub enum ArgKind {
    Value { option: bool },
}

#[derive(Debug, Clone)]
pub enum FieldMode {
    Argument,
    Property { name: Option<String> },
    Arguments,
    Properties,
    Children { name: Option<String> },
    Child,
    Flatten(Flatten),
    Span,
    NodeName,
    TypeName,
}

pub enum FlattenItem {
    Child,
    Property,
}

#[derive(Debug, Clone)]
pub struct Flatten {
    child: bool,
    property: bool,
}

#[derive(Debug, Clone)]
pub enum DecodeMode {
    Normal,
    Str,
    Bytes,
}

#[derive(Debug)]
pub enum Attr {
    Skip,
    DecodeMode(DecodeMode),
    FieldMode(FieldMode),
    Unwrap(FieldAttrs),
    Default(Option<syn::Expr>),
    SpanType(syn::Type),
    /// When applied to newtype enum variants, delegate all parsing to the inner type
    Transparent,
}

#[derive(Debug, Clone)]
pub struct FieldAttrs {
    pub mode: Option<FieldMode>,
    pub decode: Option<(DecodeMode, Span)>,
    pub unwrap: Option<Box<FieldAttrs>>,
    pub default: Option<Option<syn::Expr>>,
}

#[derive(Debug, Clone)]
pub struct VariantAttrs {
    pub skip: bool,
    /// Delegate all parsing to the inner type (on newtype enum variants)
    pub transparent: bool,
}

#[derive(Clone)]
pub enum AttrAccess {
    Indexed(usize),
    Named(syn::Ident),
}

#[derive(Clone)]
pub struct Field {
    pub span: Span,
    pub attr: AttrAccess,
    pub tmp_name: syn::Ident,
}

pub struct SpanField {
    pub field: Field,
}

pub struct NodeNameField {
    pub field: Field,
}

pub struct TypeNameField {
    pub field: Field,
    pub option: bool,
}

pub struct Arg {
    pub field: Field,
    pub kind: ArgKind,
    pub decode: DecodeMode,
    pub default: Option<Option<syn::Expr>>,
    pub option: bool,
}

pub struct VarArgs {
    pub field: Field,
    pub decode: DecodeMode,
}

pub struct Prop {
    pub field: Field,
    pub name: String,
    pub option: bool,
    pub decode: DecodeMode,
    pub flatten: bool,
    pub default: Option<Option<syn::Expr>>,
}

pub struct VarProps {
    pub field: Field,
    pub decode: DecodeMode,
}

pub enum ChildMode {
    Normal,
    Flatten,
    Multi,
    Bool,
}

pub struct Child {
    pub field: Field,
    pub name: String,
    pub option: bool,
    pub mode: ChildMode,
    pub unwrap: Option<Box<FieldAttrs>>,
    pub default: Option<Option<syn::Expr>>,
}

pub struct VarChildren {
    pub field: Field,
    pub unwrap: Option<Box<FieldAttrs>>,
}

pub enum ExtraKind {
    Auto,
}

pub struct ExtraField {
    pub field: Field,
    pub kind: ExtraKind,
    /// If the type is not Option, is None
    /// If the type is Option, is Some(inner type)
    pub option: Option<Type>,
}

#[derive(Clone)]
pub struct TraitProps {
    pub span_type: Option<syn::Type>,
}

pub struct Struct {
    pub ident: syn::Ident,
    pub trait_props: TraitProps,
    pub generics: syn::Generics,
    pub spans: Vec<SpanField>,
    pub node_names: Vec<NodeNameField>,
    pub type_names: Vec<TypeNameField>,
    pub arguments: Vec<Arg>,
    pub var_args: Option<VarArgs>,
    pub properties: Vec<Prop>,
    pub var_props: Option<VarProps>,
    pub has_arguments: bool,
    pub has_properties: bool,
    pub children: Vec<Child>,
    pub var_children: Option<VarChildren>,
    pub extra_fields: Vec<ExtraField>,
}

pub struct StructBuilder {
    pub ident: syn::Ident,
    pub trait_props: TraitProps,
    pub generics: syn::Generics,
    pub spans: Vec<SpanField>,
    pub node_names: Vec<NodeNameField>,
    pub type_names: Vec<TypeNameField>,
    pub arguments: Vec<Arg>,
    pub var_args: Option<VarArgs>,
    pub properties: Vec<Prop>,
    pub var_props: Option<VarProps>,
    pub children: Vec<Child>,
    pub var_children: Option<VarChildren>,
    pub extra_fields: Vec<ExtraField>,
}

pub struct NewType {
    pub ident: syn::Ident,
}

pub struct Variant {
    pub ident: syn::Ident,
    pub name: String,
    pub kind: VariantKind,
}

pub struct Enum {
    pub ident: syn::Ident,
    pub trait_props: TraitProps,
    pub generics: syn::Generics,
    pub variants: Vec<Variant>,
}

impl TraitProps {
    fn pick_from(attrs: &mut Vec<(Attr, Span)>) -> TraitProps {
        let mut props = TraitProps { span_type: None };
        for attr in mem::take(attrs) {
            match attr.0 {
                Attr::SpanType(ty) => {
                    props.span_type = Some(ty);
                }
                _ => attrs.push(attr),
            }
        }
        props
    }
}

fn err_pair(s1: &Field, s2: &Field, t1: &str, t2: &str) -> syn::Error {
    let mut err = syn::Error::new(s1.span, t1);
    err.combine(syn::Error::new(s2.span, t2));
    err
}

/// # Returns
///
/// If the value is not an option, return `None`
/// If the value is an option, return `Some(inner type)`
fn is_option(ty: &syn::Type) -> Option<Type> {
    if let syn::Type::Path(syn::TypePath {
        qself: None,
        path: syn::Path {
            leading_colon: None,
            segments,
        },
    }) = ty
    {
        if let Some(segment) = segments.first() {
            if segment.ident == "Option" {
                if let PathArguments::AngleBracketed(args) = &segment.arguments {
                    if let Some(GenericArgument::Type(ty)) = args.args.first() {
                        return Some(ty.clone());
                    }
                }
            }
        }
    }

    None
}

fn is_bool(ty: &syn::Type) -> bool {
    matches!(ty,
        syn::Type::Path(syn::TypePath { qself: None, path })
        if path.is_ident("bool")
    )
}

impl Variant {
    fn new(ident: syn::Ident, _attrs: VariantAttrs, kind: VariantKind) -> syn::Result<Self> {
        let name = heck::ToKebabCase::to_kebab_case(&ident.unraw().to_string()[..]);
        Ok(Variant { ident, name, kind })
    }
}

impl Enum {
    fn new(
        ident: syn::Ident,
        attrs: Vec<syn::Attribute>,
        generics: syn::Generics,
        src_variants: impl Iterator<Item = syn::Variant>,
    ) -> syn::Result<Self> {
        let mut attrs = parse_attr_list(&attrs);
        let trait_props = TraitProps::pick_from(&mut attrs);
        if !attrs.is_empty() {
            for (_, span) in attrs {
                emit_error!(span, "unexpected container attribute");
            }
        }

        let mut variants = Vec::new();
        for var in src_variants {
            let mut attrs = VariantAttrs::new();
            attrs.update(parse_attr_list(&var.attrs));
            if attrs.skip {
                continue;
            }
            let kind = match var.fields {
                syn::Fields::Named(_) => VariantKind::Named,
                syn::Fields::Unnamed(u) => {
                    let first_field = u.unnamed.first().cloned();
                    let tup = Struct::new(
                        var.ident.clone(),
                        trait_props.clone(),
                        generics.clone(),
                        u.unnamed.into_iter(),
                    )?;
                    if tup.all_fields().len() == 1
                        && tup.extra_fields.len() == 1
                        && matches!(tup.extra_fields[0].kind, ExtraKind::Auto)
                    {
                        let first_field = first_field.expect("len == 1");
                        let span = first_field.span();
                        let ty = match first_field.ty {
                            Type::Path(ty) => ty,
                            Type::Group(ty) => {
                                let Type::Path(ty) = *ty.elem else {
                                    abort!(span, "type must be a path");
                                };
                                ty
                            }
                            _ => abort!(span, "type must be a path"),
                        };

                        // Single tuple variant without any defition means
                        // the first field inside is meant to be full node
                        // parser.
                        VariantKind::Nested {
                            option: tup.extra_fields[0].option.clone(),
                            transparent: attrs.transparent,
                            inner_ty: ty,
                        }
                    } else {
                        VariantKind::Tuple(tup)
                    }
                }
                syn::Fields::Unit => VariantKind::Unit,
            };
            variants.push(Variant::new(var.ident, attrs, kind)?);
        }
        Ok(Enum {
            ident,
            trait_props,
            generics,
            variants,
        })
    }
}

impl StructBuilder {
    pub fn new(ident: syn::Ident, trait_props: TraitProps, generics: syn::Generics) -> Self {
        StructBuilder {
            ident,
            trait_props,
            generics,
            spans: Vec::new(),
            node_names: Vec::new(),
            type_names: Vec::new(),
            arguments: Vec::new(),
            var_args: None::<VarArgs>,
            properties: Vec::new(),
            var_props: None::<VarProps>,
            children: Vec::new(),
            var_children: None::<VarChildren>,
            extra_fields: Vec::new(),
        }
    }
    pub fn build(self) -> Struct {
        Struct {
            ident: self.ident,
            trait_props: self.trait_props,
            generics: self.generics,
            spans: self.spans,
            node_names: self.node_names,
            type_names: self.type_names,
            has_arguments: !self.arguments.is_empty() || self.var_args.is_some(),
            has_properties: !self.properties.is_empty() || self.var_props.is_some(),
            arguments: self.arguments,
            var_args: self.var_args,
            properties: self.properties,
            var_props: self.var_props,
            children: self.children,
            var_children: self.var_children,
            extra_fields: self.extra_fields,
        }
    }
    pub fn add_field(
        &mut self,
        field: Field,
        is_option: Option<Type>,
        is_bool: bool,
        attrs: &FieldAttrs,
    ) -> syn::Result<&mut Self> {
        match &attrs.mode {
            Some(FieldMode::Argument) => {
                if let Some(prev) = &self.var_args {
                    return Err(err_pair(
                        &field,
                        &prev.field,
                        "extra `argument` after capture all `arguments`",
                        "capture all `arguments` is defined here",
                    ));
                }
                self.arguments.push(Arg {
                    field,
                    kind: ArgKind::Value {
                        option: is_option.is_some(),
                    },
                    decode: attrs
                        .decode
                        .as_ref()
                        .map(|(v, _)| v.clone())
                        .unwrap_or(DecodeMode::Normal),
                    default: attrs.default.clone(),
                    option: is_option.is_some(),
                });
            }
            Some(FieldMode::Arguments) => {
                if let Some(prev) = &self.var_args {
                    return Err(err_pair(
                        &field,
                        &prev.field,
                        "only single `arguments` allowed",
                        "previous `arguments` is defined here",
                    ));
                }
                self.var_args = Some(VarArgs {
                    field,
                    decode: attrs
                        .decode
                        .as_ref()
                        .map(|(v, _)| v.clone())
                        .unwrap_or(DecodeMode::Normal),
                });
            }
            Some(FieldMode::Property { name }) => {
                if let Some(prev) = &self.var_props {
                    return Err(err_pair(
                        &field,
                        &prev.field,
                        "extra `property` after capture all `properties`",
                        "capture all `properties` is defined here",
                    ));
                }
                let name = match (name, &field.attr) {
                    (Some(name), _) => name.clone(),
                    (None, AttrAccess::Named(name)) => {
                        heck::ToKebabCase::to_kebab_case(&name.unraw().to_string()[..])
                    }
                    (None, AttrAccess::Indexed(_)) => {
                        return Err(syn::Error::new(
                            field.span,
                            "property must be named, try \
                             `property(name=\"something\")",
                        ));
                    }
                };
                self.properties.push(Prop {
                    field,
                    name,
                    option: is_option.is_some(),
                    decode: attrs
                        .decode
                        .as_ref()
                        .map(|(v, _)| v.clone())
                        .unwrap_or(DecodeMode::Normal),
                    flatten: false,
                    default: attrs.default.clone(),
                });
            }
            Some(FieldMode::Properties) => {
                if let Some(prev) = &self.var_props {
                    return Err(err_pair(
                        &field,
                        &prev.field,
                        "only single `properties` is allowed",
                        "previous `properties` is defined here",
                    ));
                }
                self.var_props = Some(VarProps {
                    field,
                    decode: attrs
                        .decode
                        .as_ref()
                        .map(|(v, _)| v.clone())
                        .clone()
                        .unwrap_or(DecodeMode::Normal),
                });
            }
            Some(FieldMode::Child) => {
                attrs.no_decode("children");
                if let Some(prev) = &self.var_children {
                    return Err(err_pair(
                        &field,
                        &prev.field,
                        "extra `child` after capture all `children`",
                        "capture all `children` is defined here",
                    ));
                }
                let name = match &field.attr {
                    AttrAccess::Named(n) => {
                        heck::ToKebabCase::to_kebab_case(&n.unraw().to_string()[..])
                    }
                    AttrAccess::Indexed(_) => {
                        return Err(syn::Error::new(
                            field.span,
                            "`child` is not allowed for tuple structs",
                        ));
                    }
                };
                self.children.push(Child {
                    name,
                    field,
                    option: is_option.is_some(),
                    mode: if attrs.unwrap.is_none() && is_bool {
                        ChildMode::Bool
                    } else {
                        ChildMode::Normal
                    },
                    unwrap: attrs.unwrap.clone(),
                    default: attrs.default.clone(),
                });
            }
            Some(FieldMode::Children { name: Some(name) }) => {
                attrs.no_decode("children");
                if let Some(prev) = &self.var_children {
                    return Err(err_pair(
                        &field,
                        &prev.field,
                        "extra `children(name=` after capture all `children`",
                        "capture all `children` is defined here",
                    ));
                }
                self.children.push(Child {
                    name: name.clone(),
                    field,
                    option: is_option.is_some(),
                    mode: ChildMode::Multi,
                    unwrap: attrs.unwrap.clone(),
                    default: attrs.default.clone(),
                });
            }
            Some(FieldMode::Children { name: None }) => {
                attrs.no_decode("children");
                if let Some(prev) = &self.var_children {
                    return Err(err_pair(
                        &field,
                        &prev.field,
                        "only single catch all `children` is allowed",
                        "previous `children` is defined here",
                    ));
                }
                self.var_children = Some(VarChildren {
                    field,
                    unwrap: attrs.unwrap.clone(),
                });
            }
            Some(FieldMode::Flatten(flatten)) => {
                if is_option.is_some() {
                    return Err(syn::Error::new(
                        field.span,
                        "optional flatten fields are not supported yet",
                    ));
                }
                attrs.no_decode("children");
                if flatten.property {
                    if let Some(prev) = &self.var_props {
                        return Err(err_pair(
                            &field,
                            &prev.field,
                            "extra `flatten(property)` after \
                            capture all `properties`",
                            "capture all `properties` is defined here",
                        ));
                    }
                    self.properties.push(Prop {
                        field: field.clone(),
                        name: "".into(), // irrelevant
                        option: is_option.is_some(),
                        decode: DecodeMode::Normal,
                        flatten: true,
                        default: None,
                    });
                }
                if flatten.child {
                    if let Some(prev) = &self.var_children {
                        return Err(err_pair(
                            &field,
                            &prev.field,
                            "extra `flatten(child)` after \
                            capture all `children`",
                            "capture all `children` is defined here",
                        ));
                    }
                    self.children.push(Child {
                        name: "".into(), // unused
                        field: field.clone(),
                        option: is_option.is_some(),
                        mode: ChildMode::Flatten,
                        unwrap: None,
                        default: None,
                    });
                }
            }
            Some(FieldMode::Span) => {
                attrs.no_decode("span");
                self.spans.push(SpanField { field });
            }
            Some(FieldMode::NodeName) => {
                attrs.no_decode("node_name");
                self.node_names.push(NodeNameField { field });
            }
            Some(FieldMode::TypeName) => {
                attrs.no_decode("type_name");
                self.type_names.push(TypeNameField {
                    field,
                    option: is_option.is_some(),
                });
            }
            None => {
                self.extra_fields.push(ExtraField {
                    field,
                    kind: ExtraKind::Auto,
                    option: is_option,
                });
            }
        }
        Ok(self)
    }
}

impl Struct {
    fn new(
        ident: syn::Ident,
        trait_props: TraitProps,
        generics: syn::Generics,
        fields: impl Iterator<Item = syn::Field>,
    ) -> syn::Result<Self> {
        let mut bld = StructBuilder::new(ident, trait_props, generics);
        for (idx, fld) in fields.enumerate() {
            let mut attrs = FieldAttrs::new();
            attrs.update(parse_attr_list(&fld.attrs));
            let field = Field::new(&fld, idx);
            bld.add_field(field, is_option(&fld.ty), is_bool(&fld.ty), &attrs)?;
        }

        Ok(bld.build())
    }
    pub fn all_fields(&self) -> Vec<&Field> {
        let mut res = Vec::new();
        res.extend(self.spans.iter().map(|a| &a.field));
        res.extend(self.node_names.iter().map(|a| &a.field));
        res.extend(self.type_names.iter().map(|a| &a.field));
        res.extend(self.arguments.iter().map(|a| &a.field));
        res.extend(self.var_args.iter().map(|a| &a.field));
        res.extend(self.properties.iter().map(|p| &p.field));
        res.extend(self.var_props.iter().map(|p| &p.field));
        res.extend(self.children.iter().map(|c| &c.field));
        res.extend(self.var_children.iter().map(|c| &c.field));
        res.extend(self.extra_fields.iter().map(|f| &f.field));
        res
    }
}

impl Parse for Definition {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut attrs = input.call(syn::Attribute::parse_outer)?;
        let ahead = input.fork();
        let _vis: syn::Visibility = ahead.parse()?;

        let lookahead = ahead.lookahead1();
        if lookahead.peek(syn::Token![struct]) {
            let item: syn::ItemStruct = input.parse()?;
            attrs.extend(item.attrs);

            let mut attrs = parse_attr_list(&attrs);
            let trait_props = TraitProps::pick_from(&mut attrs);
            if !attrs.is_empty() {
                for (_, span) in attrs {
                    emit_error!(span, "unexpected container attribute");
                }
            }

            match item.fields {
                syn::Fields::Named(n) => {
                    Struct::new(item.ident, trait_props, item.generics, n.named.into_iter())
                        .map(Definition::Struct)
                }
                syn::Fields::Unnamed(u) => {
                    let tup = Struct::new(
                        item.ident.clone(),
                        trait_props.clone(),
                        item.generics.clone(),
                        u.unnamed.into_iter(),
                    )?;
                    if tup.all_fields().len() == 1
                        && tup.extra_fields.len() == 1
                        && matches!(tup.extra_fields[0].kind, ExtraKind::Auto)
                    {
                        Ok(Definition::NewType(NewType { ident: item.ident }))
                    } else {
                        Ok(Definition::TupleStruct(tup))
                    }
                }
                syn::Fields::Unit => Struct::new(
                    item.ident,
                    trait_props,
                    item.generics,
                    Vec::new().into_iter(),
                )
                .map(Definition::UnitStruct),
            }
        } else if lookahead.peek(syn::Token![enum]) {
            let item: syn::ItemEnum = input.parse()?;
            attrs.extend(item.attrs);
            Enum::new(item.ident, attrs, item.generics, item.variants.into_iter())
                .map(Definition::Enum)
        } else {
            Err(lookahead.error())
        }
    }
}

impl FieldAttrs {
    fn new() -> FieldAttrs {
        FieldAttrs {
            mode: None,
            decode: None,
            unwrap: None,
            default: None,
        }
    }
    fn update(&mut self, attrs: impl IntoIterator<Item = (Attr, Span)>) {
        use Attr::*;

        for (attr, span) in attrs {
            match attr {
                FieldMode(mode) => {
                    if self.mode.is_some() {
                        emit_error!(
                            span,
                            "only single attribute that defines mode of the \
                            field is allowed. Perhaps you mean `unwrap`?"
                        );
                    }
                    self.mode = Some(mode);
                }
                Unwrap(val) => {
                    if self.unwrap.is_some() {
                        emit_error!(span, "`unwrap` specified twice");
                    }
                    self.unwrap = Some(Box::new(val));
                }
                DecodeMode(mode) => {
                    if self.decode.is_some() {
                        emit_error!(
                            span,
                            "only single attribute that defines parser of the \
                            field is allowed"
                        );
                    }
                    self.decode = Some((mode, span));
                }
                Default(value) => {
                    if self.default.is_some() {
                        emit_error!(span, "only single default is allowed");
                    }
                    self.default = Some(value);
                }
                _ => emit_error!(span, "this attribute is not supported on fields"),
            }
        }
    }

    fn no_decode(&self, element: &str) {
        if let Some((mode, span)) = self.decode.as_ref() {
            if self.unwrap.is_some() {
                emit_error!(span,
                    "decode modes are not supported on {}", element;
                    hint= (*span) => "try putting decode mode \
                                          into unwrap(.., {})", mode;
                );
            } else {
                emit_error!(span, "decode modes are not supported on {}", element);
            }
        }
    }
}

impl VariantAttrs {
    fn new() -> VariantAttrs {
        VariantAttrs {
            skip: false,
            transparent: false,
        }
    }
    fn update(&mut self, attrs: impl IntoIterator<Item = (Attr, Span)>) {
        use Attr::*;

        for (attr, span) in attrs {
            match attr {
                Skip => self.skip = true,
                Transparent => self.transparent = true,
                _ => emit_error!(span, "not supported on enum variants"),
            }
        }
    }
}

fn parse_attr_list(attrs: &[syn::Attribute]) -> Vec<(Attr, Span)> {
    let mut all = Vec::new();
    for attr in attrs {
        if matches!(attr.style, syn::AttrStyle::Outer) && attr.path().is_ident("knus") {
            match attr.parse_args_with(parse_attrs) {
                Ok(attrs) => all.extend(attrs),
                Err(e) => emit_error!(e),
            }
        }
    }
    all
}

fn parse_attrs(input: ParseStream) -> syn::Result<impl IntoIterator<Item = (Attr, Span)> + use<>> {
    Punctuated::<_, syn::Token![,]>::parse_terminated_with(input, Attr::parse)
}

impl Attr {
    fn parse(input: ParseStream) -> syn::Result<(Self, Span)> {
        let span = input.span();
        Self::_parse(input).map(|a| (a, span))
    }
    fn _parse(input: ParseStream) -> syn::Result<Self> {
        let lookahead = input.lookahead1();
        if lookahead.peek(kw::transparent) {
            let _kw: kw::transparent = input.parse()?;
            Ok(Attr::Transparent)
        } else if lookahead.peek(kw::argument) {
            let _kw: kw::argument = input.parse()?;
            Ok(Attr::FieldMode(FieldMode::Argument))
        } else if lookahead.peek(kw::arguments) {
            let _kw: kw::arguments = input.parse()?;
            Ok(Attr::FieldMode(FieldMode::Arguments))
        } else if lookahead.peek(kw::property) {
            let _kw: kw::property = input.parse()?;
            let mut name = None;
            if !input.is_empty() && !input.lookahead1().peek(syn::Token![,]) {
                let parens;
                syn::parenthesized!(parens in input);
                let lookahead = parens.lookahead1();
                if lookahead.peek(kw::name) {
                    let _kw: kw::name = parens.parse()?;
                    let _eq: syn::Token![=] = parens.parse()?;
                    let name_lit: syn::LitStr = parens.parse()?;
                    name = Some(name_lit.value());
                } else {
                    return Err(lookahead.error());
                }
            }
            Ok(Attr::FieldMode(FieldMode::Property { name }))
        } else if lookahead.peek(kw::properties) {
            let _kw: kw::properties = input.parse()?;
            Ok(Attr::FieldMode(FieldMode::Properties))
        } else if lookahead.peek(kw::children) {
            let _kw: kw::children = input.parse()?;
            let mut name = None;
            if !input.is_empty() && !input.lookahead1().peek(syn::Token![,]) {
                let parens;
                syn::parenthesized!(parens in input);
                let lookahead = parens.lookahead1();
                if lookahead.peek(kw::name) {
                    let _kw: kw::name = parens.parse()?;
                    let _eq: syn::Token![=] = parens.parse()?;
                    let name_lit: syn::LitStr = parens.parse()?;
                    name = Some(name_lit.value());
                } else {
                    return Err(lookahead.error());
                }
            }
            Ok(Attr::FieldMode(FieldMode::Children { name }))
        } else if lookahead.peek(kw::child) {
            let _kw: kw::child = input.parse()?;
            Ok(Attr::FieldMode(FieldMode::Child))
        } else if lookahead.peek(kw::unwrap) {
            let _kw: kw::unwrap = input.parse()?;
            let parens;
            syn::parenthesized!(parens in input);
            let mut attrs = FieldAttrs::new();
            let chunk = parens.call(parse_attrs)?;
            attrs.update(chunk);
            Ok(Attr::Unwrap(attrs))
        } else if lookahead.peek(kw::skip) {
            let _kw: kw::skip = input.parse()?;
            Ok(Attr::Skip)
        } else if lookahead.peek(kw::str) {
            let _kw: kw::str = input.parse()?;
            Ok(Attr::DecodeMode(DecodeMode::Str))
        } else if lookahead.peek(kw::bytes) {
            let _kw: kw::bytes = input.parse()?;
            Ok(Attr::DecodeMode(DecodeMode::Bytes))
        } else if lookahead.peek(kw::flatten) {
            let _kw: kw::flatten = input.parse()?;
            let parens;
            syn::parenthesized!(parens in input);
            let items = Punctuated::<FlattenItem, syn::Token![,]>::parse_terminated(&parens)?;
            let mut flatten = Flatten {
                child: false,
                property: false,
            };
            for item in items {
                match item {
                    FlattenItem::Child => flatten.child = true,
                    FlattenItem::Property => flatten.property = true,
                }
            }
            Ok(Attr::FieldMode(FieldMode::Flatten(flatten)))
        } else if lookahead.peek(kw::default) {
            let _kw: kw::default = input.parse()?;
            if !input.is_empty() && !input.lookahead1().peek(syn::Token![,]) {
                let _eq: syn::Token![=] = input.parse()?;
                let value: syn::Expr = input.parse()?;
                Ok(Attr::Default(Some(value)))
            } else {
                Ok(Attr::Default(None))
            }
        } else if lookahead.peek(kw::span) {
            let _kw: kw::span = input.parse()?;
            Ok(Attr::FieldMode(FieldMode::Span))
        } else if lookahead.peek(kw::node_name) {
            let _kw: kw::node_name = input.parse()?;
            Ok(Attr::FieldMode(FieldMode::NodeName))
        } else if lookahead.peek(kw::type_name) {
            let _kw: kw::type_name = input.parse()?;
            Ok(Attr::FieldMode(FieldMode::TypeName))
        } else if lookahead.peek(kw::span_type) {
            let _kw: kw::span_type = input.parse()?;
            let _eq: syn::Token![=] = input.parse()?;
            let ty: syn::Type = input.parse()?;
            Ok(Attr::SpanType(ty))
        } else {
            Err(lookahead.error())
        }
    }
}

impl Parse for FlattenItem {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let lookahead = input.lookahead1();
        if lookahead.peek(kw::child) {
            let _kw: kw::child = input.parse()?;
            Ok(FlattenItem::Child)
        } else if lookahead.peek(kw::property) {
            let _kw: kw::property = input.parse()?;
            Ok(FlattenItem::Property)
        } else {
            Err(lookahead.error())
        }
    }
}

impl Field {
    pub fn new_named(name: &syn::Ident) -> Field {
        Field {
            span: name.span(),
            attr: AttrAccess::Named(name.clone()),
            tmp_name: name.clone(),
        }
    }
    fn new(field: &syn::Field, idx: usize) -> Field {
        field
            .ident
            .as_ref()
            .map(|id| Field {
                span: field.span(),
                attr: AttrAccess::Named(id.clone()),
                tmp_name: id.clone(),
            })
            .unwrap_or_else(|| Field {
                span: field.span(),
                attr: AttrAccess::Indexed(idx),
                tmp_name: syn::Ident::new(&format!("field{}", idx), Span::mixed_site()),
            })
    }
    pub fn as_token_stream(&self) -> TokenStream {
        match &self.attr {
            AttrAccess::Indexed(idx) => quote!(self.#idx),
            AttrAccess::Named(name) => quote!(self.#name),
        }
    }
    pub fn is_indexed(&self) -> bool {
        matches!(self.attr, AttrAccess::Indexed(_))
    }
    pub fn as_index(&self) -> Option<usize> {
        match &self.attr {
            AttrAccess::Indexed(idx) => Some(*idx),
            AttrAccess::Named(_) => None,
        }
    }
    pub fn as_assign_pair(&self) -> Option<TokenStream> {
        match &self.attr {
            AttrAccess::Indexed(_) => None,
            AttrAccess::Named(n) if n == &self.tmp_name => Some(quote!(#n)),
            AttrAccess::Named(n) => {
                let tmp_name = &self.tmp_name;
                Some(quote!(#n: #tmp_name))
            }
        }
    }
}

impl fmt::Display for DecodeMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use DecodeMode::*;

        match self {
            Normal => "normal",
            Str => "str",
            Bytes => "bytes",
        }
        .fmt(f)
    }
}
