#!/usr/bin/env bash
set -euo pipefail

pick_gcc() {
  local c
  for c in \
    "${CARGO_TARGET_MIPSEL_UNKNOWN_LINUX_MUSL_LINKER:-}" \
    "${CARGO_TARGET_MIPS_UNKNOWN_LINUX_MUSL_LINKER:-}" \
    mipsel-linux-muslsf-gcc mips-linux-muslsf-gcc \
    mipsel-unknown-linux-musl-gcc mips-unknown-linux-musl-gcc \
    mipsel-linux-musl-gcc mips-linux-musl-gcc \
    gcc
  do
    [ -n "$c" ] && command -v "$c" >/dev/null 2>&1 && { printf '%s\n' "$c"; return 0; }
  done
  return 1
}

gcc=$(pick_gcc) || {
  echo "cross-provide-libunwind: no gcc on PATH" >&2
  exit 1
}

libgcc=$("$gcc" -print-libgcc-file-name)
libdir=$(dirname "$libgcc")
eh="$libdir/libgcc_eh.a"
if [ ! -f "$eh" ]; then
  echo "cross-provide-libunwind: no libgcc_eh.a next to $libgcc" >&2
  exit 1
fi

mkdir -p /usr/local/harbor-libunwind
cp -f "$eh" /usr/local/harbor-libunwind/libunwind.a
echo "cross-provide-libunwind: /usr/local/harbor-libunwind/libunwind.a <- $eh ($gcc)"
ln -sfn libgcc_eh.a "$libdir/libunwind.a" 2>/dev/null || true
