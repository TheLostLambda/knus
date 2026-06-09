use std::fmt::Write;

use criterion::{Criterion, criterion_group, criterion_main};
use knus::parse_ast;
use knus::span::Span;

/// Build a representative KDL document by repeating a block that exercises a
/// variety of grammar productions: bare and quoted args, properties, nested
/// children, numbers, and type annotations.
fn sample_document(blocks: usize) -> String {
    let mut doc = String::new();
    for i in 0..blocks {
        write!(
            doc,
            r#"
plugin "name-{i}" url="https://example.com/{i}" enabled=true {{
    version "1.{i}.0"
    settings count={i} ratio=3.1415 label="some quoted value with spaces" {{
        nested (i32)42 flag=false {{
            leaf "a" "b" "c" key="value"
        }}
    }}
    // a comment to skip
    tags "alpha" "beta" "gamma"
}}
"#
        )
        .unwrap();
    }
    doc
}

fn bench_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse_ast");
    for &blocks in &[1usize, 50, 500] {
        let doc = sample_document(blocks);
        group.throughput(criterion::Throughput::Bytes(doc.len() as u64));
        group.bench_function(format!("{blocks}_blocks"), |b| {
            b.iter(|| parse_ast::<Span>("bench.kdl", std::hint::black_box(&doc)).unwrap());
        });
    }
    group.finish();
}

criterion_group!(benches, bench_parse);
criterion_main!(benches);
