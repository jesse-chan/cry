#!/usr/bin/env bash
set -e

# 切換至腳本所在目錄
cd "$(dirname "$0")"

echo "📦 正在安裝依賴..."
npm install

echo "🔨 正在編譯 TypeScript..."
npm run build

echo "🔗 正在註冊全域 cry 指令 (npm link)..."
npm link

echo ""
echo "✅ 安裝完成！現在可以在任何地方使用 cry 指令："
echo "   加密: cry -e \"文字\""
echo "   解密: cry -d \"密文\""
