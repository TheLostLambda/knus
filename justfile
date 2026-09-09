watch:
  watchexec -e rs,toml just test

test:
  cargo test --workspace

# Run the official KDL test suite. Requires $KNUS_KDL_TEST_CASES to point at the
# tests/test_cases directory of a https://github.com/kdl-org/kdl checkout.
# An optional argument filters cases by substring, e.g. `just conformance escline`.
conformance *filter:
  cargo run --example conformance -- {{filter}}

# Run the implementation-agnostic KDL test suite
# (https://github.com/kdl-org/kdl-test). Requires the `kdl-test` binary on $PATH.
# An optional argument selects individual cases, e.g.
# `just kdl-test valid/arg_bare.kdl`.
kdl-test *tests:
  cargo build --release --example kdl_test_decoder
  kdl-test run --decoder examples/kdl_test_decoder.sh {{tests}}

lint:
  cargo fmt --check
  cargo clippy --workspace --all-targets

cov:
  cargo +nightly llvm-cov --workspace --branch --open

ci-cov:
  cargo +nightly llvm-cov --workspace --branch --codecov --output-path codecov.json

check-wasm:
  cargo check --workspace --target wasm32-unknown-unknown

min-versions:
  cargo +nightly test --workspace -Z direct-minimal-versions
