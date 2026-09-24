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

# 設定密語：寫入使用者的 shell 設定檔，不會進 repo
case "$SHELL" in
  */zsh) RC="$HOME/.zshrc" ;;
  *) RC="$HOME/.bashrc" ;;
esac
if ! grep -q 'export CRY_KEY=' "$RC" 2>/dev/null; then
  echo ""
  read -rsp "🔑 請設定 CRY_KEY 密語（輸入時不會顯示）: " key; echo
  if [ -z "$key" ]; then
    echo "⚠️  未輸入密語，略過。之後可在 $RC 加入 export CRY_KEY=\"你的密語\""
  else
    printf 'export CRY_KEY=%q\n' "$key" >> "$RC"
    echo "已寫入 $RC，請執行 source $RC 或重開終端機"
  fi
fi

echo ""
echo "✅ 安裝完成！現在可以在任何地方使用 cry 指令："
echo "   加密: cry -e \"文字\""
echo "   解密: cry -d \"密文\""
