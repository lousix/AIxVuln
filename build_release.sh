#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WAILS_DIR="$ROOT_DIR/wailsapp/AIxVulnGUI"
RELEASE_DIR="$ROOT_DIR/release"

# 检测当前系统和架构
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) GOARCH="amd64" ;;
  aarch64|arm64) GOARCH="arm64" ;;
  *) echo "不支持的架构: $ARCH"; exit 1 ;;
esac

echo "=========================================="
echo "  AIxVuln 构建脚本"
echo "  系统: ${OS}/${GOARCH}"
echo "=========================================="

mkdir -p "$RELEASE_DIR"

# 复制 dockerfile/ 到 Wails 目录供 go:embed 使用
WAILS_DOCKERFILE_DIR="$WAILS_DIR/dockerfile"
rm -rf "$WAILS_DOCKERFILE_DIR"
cp -R "$ROOT_DIR/dockerfile" "$WAILS_DOCKERFILE_DIR"
trap 'rm -rf "$WAILS_DOCKERFILE_DIR"' EXIT

# ──────────────────────────────────────────────
# 1) GUI 版本 (Wails)
# ──────────────────────────────────────────────
echo ""
echo "[1/2] 构建 GUI 版本 (Wails)..."

WAILS_BIN="$HOME/go/bin/wails"
if [ ! -x "$WAILS_BIN" ]; then
  if command -v wails >/dev/null 2>&1; then
    WAILS_BIN="$(command -v wails)"
  else
    echo "⚠ wails 未找到，跳过 GUI 构建"
    echo "  安装: https://wails.io/docs/gettingstarted/installation"
    WAILS_BIN=""
  fi
fi

if [ -n "$WAILS_BIN" ]; then
  (
    cd "$WAILS_DIR"
    "$WAILS_BIN" build -clean -platform "${OS}/${GOARCH}"
  )
  if [ "$OS" = "darwin" ]; then
    GUI_SRC="$WAILS_DIR/build/bin/AIxVulnGUI.app"
    GUI_DST="$RELEASE_DIR/AIxVulnGUI-${OS}-${GOARCH}.app"
    rm -rf "$GUI_DST"
    cp -R "$GUI_SRC" "$GUI_DST"
  else
    GUI_SRC="$WAILS_DIR/build/bin/AIxVulnGUI"
    GUI_DST="$RELEASE_DIR/AIxVulnGUI-${OS}-${GOARCH}"
    cp "$GUI_SRC" "$GUI_DST"
    chmod +x "$GUI_DST"
  fi
  echo "✅ GUI: $GUI_DST"
fi

# ──────────────────────────────────────────────
# 2) Web-only 版本 (无 GUI 依赖，单二进制)
# ──────────────────────────────────────────────
echo ""
echo "[2/2] 构建 Web-only 版本..."

WEB_DST="$RELEASE_DIR/AIxVulnWeb-${OS}-${GOARCH}"
(
  cd "$WAILS_DIR"
  CGO_ENABLED=0 go build -o "$WEB_DST" .
)
chmod +x "$WEB_DST" || true
echo "✅ Web: $WEB_DST"

# ──────────────────────────────────────────────
echo ""
echo "=========================================="
echo "  构建完成！产物目录: $RELEASE_DIR"
ls -lh "$RELEASE_DIR"/ 2>/dev/null || true
echo "=========================================="
