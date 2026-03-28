# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is knus?

knus is a Rust KDL file format parser with derive macros for decoding KDL documents into Rust types. It uses chumsky for parsing and miette for error reporting. Forked from knuffel.

## Build & Test Commands

Uses `just` as a task runner (see `justfile`):

- `just test` — run all tests (`cargo test --workspace`)
- `just lint` — check formatting and clippy (`cargo fmt --check && cargo clippy --workspace --tests`)
- `just watch` — watch and re-run tests on changes
- `just cov` — coverage report (requires nightly + llvm-cov)
- `just check-wasm` — check wasm32 target compiles
- `cargo test -p knus-derive` — run only derive macro tests
- `cargo test -p knus-derive --test normal` — run a single test file

Version control uses **jj** (Jujutsu), not git directly.

## Workspace Structure

Two crates in one workspace:

- **`knus`** (root) — parser, AST, decode traits, error types
- **`knus-derive`** (`derive/`) — proc-macro crate providing `#[derive(Decode)]` and `#[derive(DecodeScalar)]`

## Architecture

**Parsing pipeline:** KDL text → `grammar.rs` (chumsky parser) → `ast::Document` → decode traits → user's Rust types

- `grammar.rs` — chumsky-based KDL parser producing AST
- `ast.rs` — AST types: `Document`, `Node`, `Value`, `Literal`, spans
- `traits.rs` — core traits: `Decode` (nodes), `DecodeChildren` (document root), `DecodeScalar` (values), `DecodePartial` (flattened structs), `DecodeSpan`
- `decode.rs` — `Context` struct (accumulates errors, holds extension data)
- `errors.rs` — error types using miette/thiserror
- `wrappers.rs` — public API entry points: `parse()`, `parse_ast()`, `parse_with_context()`
- `convert.rs` / `convert_ast.rs` — conversions between AST forms
- `containers.rs` — decode impls for standard library containers

**Derive macro** (`derive/`):
- `definition.rs` — parses `#[knus(...)]` attributes into an IR
- `node.rs` — codegen for struct decoding
- `variants.rs` — codegen for enum decoding
- `scalar.rs` — codegen for `DecodeScalar`
- `kw.rs` — custom keyword definitions for syn parsing

## Key Design Notes

- Edition 2024 Rust
- Parser uses a git dependency on chumsky (pre-0.13.0 unreleased commit)
- Errors use miette diagnostics — the `fancy` feature on miette is needed in consuming apps for pretty error output
- Optional features: `derive` (on by default), `base64`, `line-numbers`, `minicbor` (for CBOR serialization of AST)
- The `#[knus(...)]` attribute namespace is used on derive fields for: `argument`, `property`, `child`, `children`, `flatten`, `unwrap`, `span`, etc.
