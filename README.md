# cry

簡潔快速的字串對稱加密 / 解密 CLI 工具（基於 AES-256-GCM）。支援自動將結果寫入系統剪貼簿。

## 📥 安裝與設定

從 GitHub clone 或 pull 專案後，直接執行安裝腳本即可自動完成依賴安裝、編譯與全域指令註冊：

```bash
git clone https://github.com/jesse-chan/cry.git
cd cry
./install.sh
```

## 🚀 使用方法

### 1. 加密 (-e)
```bash
cry -e "要加密的字串"
```
* 加密結果會輸出於終端機，並自動複製至剪貼簿。

### 2. 解密 (-d)
```bash
cry -d "<密文字串>"
```
* 解密結果會輸出於終端機，並自動複製至剪貼簿。

### 3. 密語（Passphrase）
密語由環境變數 `CRY_KEY` 提供，未設定時無法執行。`install.sh` 會詢問密語並寫入 `~/.zshrc`（或 `~/.bashrc`），也可以手動加入：

```bash
export CRY_KEY="my-secret-key"
```

臨時使用其他密語：

```bash
CRY_KEY="other-key" cry -d "<密文字串>"
```

## 📱 手機 / 網頁版

`docs/` 內為網頁版，部署於 GitHub Pages：<https://jesse-chan.github.io/cry/>

* 在瀏覽器本機加解密，密文格式與 CLI 相同，可互相解密（需使用同一組密語）。
* 密語在網頁上輸入，只存在該裝置的瀏覽器中，不會寫入網頁原始碼。
* 手機上可用「加入主畫面」，之後離線也能使用。
