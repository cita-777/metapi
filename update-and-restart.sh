#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$ROOT_DIR/docker/docker-compose.yml"
COMPOSE_OVERRIDE_FILE="$ROOT_DIR/docker/docker-compose.override.yml"
ENV_FILE="$ROOT_DIR/docker/.env"
DATA_DIR="$ROOT_DIR/docker/data"

DO_PULL=0
SKIP_BACKUP=0

usage() {
  cat <<'EOF'
Usage: ./update-and-restart.sh [--pull] [--skip-backup]

默认行为:
  1. 保留现有 docker/data 数据
  2. 先备份数据目录
  3. 基于当前本地代码重新构建并重启容器

可选参数:
  --pull         先拉取最新 Git 代码后再构建。若工作区有未提交修改会直接退出，避免覆盖本地改动
  --skip-backup  跳过启动前数据备份
  -h, --help     显示帮助
EOF
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

require_file() {
  if [ ! -f "$1" ]; then
    echo "Missing required file: $1" >&2
    exit 1
  fi
}

while [ $# -gt 0 ]; do
  case "$1" in
    --pull)
      DO_PULL=1
      ;;
    --skip-backup)
      SKIP_BACKUP=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

require_cmd docker
require_cmd tar
require_cmd git
require_file "$COMPOSE_FILE"
require_file "$ENV_FILE"

COMPOSE_ARGS=(
  -f "$COMPOSE_FILE"
  --env-file "$ENV_FILE"
)

if [ -f "$COMPOSE_OVERRIDE_FILE" ]; then
  COMPOSE_ARGS=(
    -f "$COMPOSE_FILE"
    -f "$COMPOSE_OVERRIDE_FILE"
    --env-file "$ENV_FILE"
  )
fi

if [ "$DO_PULL" -eq 1 ]; then
  echo "[0/5] Checking git worktree..."
  if [ -n "$(git -C "$ROOT_DIR" status --porcelain)" ]; then
    echo "Git worktree has uncommitted changes. Commit/stash them first, or rerun without --pull to rebuild the current local code." >&2
    exit 1
  fi

  echo "[1/5] Pulling latest git changes..."
  git -C "$ROOT_DIR" pull --rebase
else
  echo "[1/4] Using current local source code..."
fi

BACKUP_FILE=""
RESTORE_ON_ERROR=0

restore_if_failed() {
  if [ "$RESTORE_ON_ERROR" -eq 1 ]; then
    echo "Update failed after containers were stopped; attempting to restore service..." >&2
    docker compose "${COMPOSE_ARGS[@]}" up -d --force-recreate || true
  fi
}

trap restore_if_failed ERR

if [ "$DO_PULL" -eq 1 ]; then
  echo "[2/5] Stopping current containers..."
else
  echo "[2/4] Stopping current containers..."
fi
docker compose "${COMPOSE_ARGS[@]}" down --remove-orphans
RESTORE_ON_ERROR=1

if [ "$SKIP_BACKUP" -eq 0 ]; then
  mkdir -p "$DATA_DIR"
  BACKUP_FILE="$ROOT_DIR/docker/data-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
  if [ "$DO_PULL" -eq 1 ]; then
    echo "[3/5] Backing up data directory..."
  else
    echo "[3/4] Backing up data directory..."
  fi
  tar -czf "$BACKUP_FILE" -C "$DATA_DIR" .
else
  if [ "$DO_PULL" -eq 1 ]; then
    echo "[3/5] Skipping data backup by request..."
  else
    echo "[3/4] Skipping data backup by request..."
  fi
fi

if [ "$DO_PULL" -eq 1 ]; then
  echo "[4/5] Rebuilding and starting containers..."
else
  echo "[4/4] Rebuilding and starting containers..."
fi
docker compose "${COMPOSE_ARGS[@]}" up -d --build --force-recreate
RESTORE_ON_ERROR=0
trap - ERR

echo
echo "Container status:"
docker compose "${COMPOSE_ARGS[@]}" ps

echo
echo "Recent logs:"
docker compose "${COMPOSE_ARGS[@]}" logs --tail 20

if [ -n "$BACKUP_FILE" ]; then
  echo
  echo "Data backup saved to: $BACKUP_FILE"
fi

if PORT_MAPPING="$(docker compose "${COMPOSE_ARGS[@]}" port metapi 4000 2>/dev/null)"; then
  echo
  echo "Service is available at: $PORT_MAPPING"
fi
