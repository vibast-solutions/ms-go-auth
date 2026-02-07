#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

PROTO_FILE="$ROOT_DIR/proto/auth.proto"
OUT_DIR="$ROOT_DIR/app/types"

if ! command -v protoc >/dev/null 2>&1; then
  echo "Error: protoc is not installed or not on PATH." >&2
  echo "Install protoc and retry." >&2
  exit 1
fi

if ! command -v protoc-gen-go >/dev/null 2>&1; then
  echo "Error: protoc-gen-go is not installed or not on PATH." >&2
  echo "Install with: go install google.golang.org/protobuf/cmd/protoc-gen-go@latest" >&2
  exit 1
fi

if ! command -v protoc-gen-go-grpc >/dev/null 2>&1; then
  echo "Error: protoc-gen-go-grpc is not installed or not on PATH." >&2
  echo "Install with: go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

protoc \
  -I "$ROOT_DIR/proto" \
  --go_out="$OUT_DIR" --go_opt=paths=source_relative \
  --go-grpc_out="$OUT_DIR" --go-grpc_opt=paths=source_relative \
  "auth.proto"

echo "Generated Go protobuf/grpc files in $OUT_DIR"
