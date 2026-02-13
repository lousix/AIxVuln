#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=========================================="
echo "  AIxVuln Docker 镜像一键构建脚本"
echo "=========================================="

echo ""
echo "[1/2] 构建 aisandbox 镜像..."
docker build -t aisandbox -f "$SCRIPT_DIR/dockerfile.aisandbox/Dockerfile" "$SCRIPT_DIR/dockerfile.aisandbox"
echo "✅ aisandbox 构建完成"

echo ""
echo "[2/2] 构建 java_env 镜像..."
docker build -t java_env -f "$SCRIPT_DIR/dockerfile.java_env/Dockerfile" "$SCRIPT_DIR/dockerfile.java_env"
echo "✅ java_env 构建完成"

echo ""
echo "=========================================="
echo "  全部镜像构建完成！"
echo "  - aisandbox"
echo "  - java_env"
echo "=========================================="
