#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WAILS_DIR="$ROOT_DIR/wailsapp/AIxVulnGUI"
RELEASE_DIR="$ROOT_DIR/release"

GOOS="linux"
GOARCH="amd64"

echo "=========================================="
echo "  AIxVuln Web-only 交叉编译"
echo "  目标: ${GOOS}/${GOARCH}"
echo "=========================================="

mkdir -p "$RELEASE_DIR"

# 复制 dockerfile/ 到 Wails 目录供 go:embed 使用
WAILS_DOCKERFILE_DIR="$WAILS_DIR/dockerfile"
rm -rf "$WAILS_DOCKERFILE_DIR"
cp -R "$ROOT_DIR/dockerfile" "$WAILS_DOCKERFILE_DIR"
trap 'rm -rf "$WAILS_DOCKERFILE_DIR"' EXIT

# 构建前端
echo ""
echo "[1/2] 构建前端..."
(
  cd "$WAILS_DIR/frontend"
  npm install --silent
  npm run build
)

# 交叉编译 Web-only 二进制
echo ""
echo "[2/2] 交叉编译 Web-only 版本 (${GOOS}/${GOARCH})..."

WEB_DST="$RELEASE_DIR/AIxVulnWeb-${GOOS}-${GOARCH}"
(
  cd "$WAILS_DIR"
  CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" go build -tags web -trimpath -ldflags="-s -w" -o "$WEB_DST" .
)
echo "✅ Web: $WEB_DST"

echo ""
echo "=========================================="
echo "  构建完成！产物目录: $RELEASE_DIR"
ls -lh "$RELEASE_DIR"/ 2>/dev/null || true
echo "=========================================="
