#!/bin/sh
# JAST build: run the full offline verification suite, then the macOS bundle.
# Usage: ./build.sh             verify + bundle
#        ./build.sh --verify-only   checks only, no bundle
set -e
cd "$(dirname "$0")"

[ -d node_modules ] || npm ci

echo "==> cargo test"
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib

echo "==> cargo clippy"
cargo clippy --locked --manifest-path src-tauri/Cargo.toml --lib -- -D warnings

echo "==> frontend build"
npm run build

echo "==> UI contract test"
npx --yes --package playwright -c 'node check-ui.cjs'

if [ "$1" = "--verify-only" ]; then
  echo "==> verification complete"
  exit 0
fi

echo "==> tauri bundle"
npm run tauri -- build --bundles app

echo "==> codesign check"
codesign --verify --deep --strict src-tauri/target/release/bundle/macos/JAST.app

echo "==> done: src-tauri/target/release/bundle/macos/JAST.app"
