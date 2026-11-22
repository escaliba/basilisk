#!/usr/bin/env bash
# Build the public Basilisk engine to WebAssembly and place the package in web/pkg,
# where the playground frontend imports it. Requires rustup (wasm32-unknown-unknown)
# and wasm-pack: `rustup target add wasm32-unknown-unknown && cargo install wasm-pack`.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "error: wasm-pack not found. Install it with: cargo install wasm-pack" >&2
  exit 1
fi

cd "$here/basilisk-wasm"
wasm-pack build --target web --release --out-dir "$here/web/pkg"

mkdir -p "$here/web/docs"
cp "$here/../docs/MACROS.md" "$here/web/docs/MACROS.md"

echo "ok: wasm package written to $here/web/pkg"
echo "ok: docs source copied to $here/web/docs/MACROS.md"
echo "serve the playground with:  python3 -m http.server -d $here/web 8080"
