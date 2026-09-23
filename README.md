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

### 3. 指定自訂密語（Passphrase）
預設使用內建密語，亦可透過環境變數 `CRY_KEY` 指定自訂密語：

```bash
CRY_KEY="my-secret-key" cry -e "機密資料"
CRY_KEY="my-secret-key" cry -d "<密文字串>"
```
