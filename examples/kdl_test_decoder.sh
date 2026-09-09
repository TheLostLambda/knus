#!/usr/bin/env bash
# Decoder entry point for the KDL test suite (https://github.com/kdl-org/kdl-test):
# reads a KDL document on stdin and writes it as JSON on stdout, exiting non-zero
# if the document does not parse.
#
#     kdl-test run --decoder examples/kdl_test_decoder.sh
#
# The suite runs this once per test case, and `cargo run` spends ~130ms
# re-resolving the workspace on every one of them even when there is nothing to
# rebuild, so exec the binary directly. It is built here only if it is missing:
# after editing the example, rebuild it yourself with
#
#     cargo build --release --example kdl_test_decoder
set -euo pipefail

# The suite may be run from anywhere, so locate the manifest rather than relying
# on the working directory.
cd "$(dirname "$(readlink -f "$0")")/.."

decoder=target/release/examples/kdl_test_decoder
# Cargo writes progress to stderr, which leaves our stdout clean for the JSON.
[ -x "$decoder" ] || cargo build --release --quiet --example kdl_test_decoder

exec "$decoder"
