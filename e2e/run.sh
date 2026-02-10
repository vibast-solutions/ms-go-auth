#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"

echo "Starting docker compose..."
docker compose -f "$COMPOSE_FILE" up -d --build

cleanup() {
  echo "Stopping docker compose..."
  docker compose -f "$COMPOSE_FILE" down -v
}
trap cleanup EXIT

echo "Running E2E tests..."
cd "$ROOT_DIR"
AUTH_HTTP_URL="${AUTH_HTTP_URL:-http://localhost:18080}" \
AUTH_GRPC_ADDR="${AUTH_GRPC_ADDR:-localhost:19090}" \
go test ./e2e -v -tags e2e
