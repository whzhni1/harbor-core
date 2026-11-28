#!/usr/bin/env bash
# Local stand-in for .github/workflows/test.yml "test (native)".
set -euo pipefail
cd "$(dirname "$0")/.."

echo '== static frontend =='
node --version
find assets -type f -name '*.js' -print0 | xargs -0 -n1 node --check
test -f assets/index.html
test -f assets/login.html
test ! -e assets/i18n-data.js
! grep -R -E '<%|%>' assets --include='*.html'
! grep -R -F '{{' assets --include='*.html'
! grep -R -F '{%' assets --include='*.html'

echo '== fmt =='
cargo fmt --all -- --check

echo '== clippy =='
cargo clippy --all-targets --locked --offline -- -D warnings

echo '== ring only =='
if cargo tree --locked --offline | grep -q aws-lc; then
  echo 'aws-lc leaked into the dependency tree' >&2
  cargo tree --locked --offline | grep aws-lc
  exit 1
fi

echo '== unit tests =='
cargo test --all-targets --locked --offline -- --test-threads=8
echo 'ci-native: ok'
