# Sepolia + Vault HTTP 本地測試（Node + ethers）

用 **Vault HTTP API**（`fetch`）操作 `blockchain/` 外掛，並用 **ethers.js v6** 在指定 **EVM chain id**（預設 **Sepolia `11155111`**，可用 **`E2E_CHAIN_ID`** 覆寫）驗證簽名、EIP-712、ECIES 與可選的鏈上廣播。**`SEPOLIA_RPC_URL` 必須對應同一條鏈**（變數名沿用，可填任意相容的 JSON-RPC URL）。

僅供本機／開發測試；請勿把 `VAULT_TOKEN`、助記詞寫進版本庫。

## 前置

1. 本機已跑 Vault，且已掛載 `blockchain/`（例如 `make setup-plugin-local`）。
2. Node 18+。
3. Phase 2 需要 Sepolia RPC URL（Infura / Alchemy / 公開 RPC 皆可）。

## 安裝

```bash
cd scripts/e2e-sepolia-js
npm install
```

## Phase 1：建立錢包與帳戶

建立一個 HD 錢包（隨機 24 詞，**不回傳助記詞**）、派生 `index 0`，再建立一個 single-key 帳戶。會寫入目錄下的 `.e2e-sepolia-state.json`（已列入 `.gitignore`）。

```bash
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root
node run.mjs phase1
```

可選環境變數：

| 變數 | 說明 |
|------|------|
| `E2E_WALLET` | 自訂 `wallet_id`（預設帶時間戳） |
| `E2E_ACCOUNT` | 自訂 single-key 名稱 |
| `KNOWN_MNEMONIC` | 若設定則改走 `import`，地址可與 `e2e_smoke.sh` 相同而可預期 |
| `KNOWN_PRIVATE_KEY` | 若設定則改走 single-key `import`（私鑰 hex，可含/不含 `0x`） |
| `E2E_CHAIN_ID` | 目標鏈 **十進位** chain id（預設 `11155111`）；寫入 `.e2e-sepolia-state.json` 的 `chainId` |

完成後依輸出到 Sepolia **水龍頭或自己的錢包** 對兩個地址打測試幣。

## Phase 2：Sepolia 驗證 + 可選廣播

```bash
export VAULT_TOKEN=root
export SEPOLIA_RPC_URL=https://sepolia.infura.io/v3/YOUR_KEY
# 可選：與 phase1 不同鏈時覆寫（優先於 state 檔里的 chainId）
# export E2E_CHAIN_ID=17000
node run.mjs phase2
```

會檢查餘額，並用 ethers 驗證：

- `sign`：`recoverAddress(keccak256(data), signature)` 與 Vault 回傳地址一致。
- `sign-eip712`：`verifyTypedData` 與 Vault 簽名一致。
- `encrypt` / `decrypt`：與 `0x68656c6c6f`（`hello`）往返。
- `sign-tx/eip1559` / `sign-tx/legacy`（**HD**）：解析 `signed_transaction`，比對 chainId / tx hash；`to` 為 single-key 地址。
- `sign-tx/eip1559` / `sign-tx/legacy`（**single-key**）：同上；`to` 為 HD 地址。

可選：實際發鏈上交易（**HD 與 single-key 至少一個地址有餘額**；各自獨立判斷）：

```bash
export BROADCAST=1
node run.mjs phase2
```

- **HD 有餘額**：廣播兩筆 **`value: 0`** 轉帳到 **single-key**（僅付 gas）：先 **EIP-1559**（nonce `n`），再 **legacy**（`n+1`）。
- **single-key 有餘額**：再廣播兩筆 **`value: 0`** 轉帳到 **HD**：先 **EIP-1559**，再 **legacy**（各自從該地址的現有 nonce 起算）。
- 兩邊皆無餘額時會失敗退出。

## Phase 3：合約部署 + access list（EIP-2930）

在 **type-2（EIP-1559）** 交易上帶入 EIP-2930 **`access_list`**（外掛僅支援 `sign-tx/eip1559`，無獨立 type-1 路徑）。腳本會：

1. 用 `ethers.getCreateAddress({ from: HD, nonce })` 預測 **CREATE** 合約地址。
2. 呼叫 `sign-tx/eip1559`：**省略 `to`**、`data` 為極小部署 bytecode、`access_list` 為 JSON 陣列（含上述地址與 `storageKeys: []`）。
3. 用 ethers 解析 `signed_transaction`：確認 **type 2**、**to 為 null**、`access_list` 非空且第一筆地址與預測一致。

可選 **上鏈**（需 HD 有足夠 Sepolia ETH 付 gas）：

```bash
export BROADCAST=1
node run.mjs phase3
```

成功後會檢查 `receipt.contractAddress` 與預測地址一致，並讀取 `code` 非空；並再呼叫 **`eth_getTransactionByHash`** 比對 `accessList` 非空（與本地解析一致），表示節點／鏈上資料也帶有 EIP-2930 access list。

### 怎麼知道 `access_list`「有帶上」vs「有幫 gas」

| 層次 | 怎麼驗證 |
|------|----------|
| **有帶進交易** | 解析 `signed_transaction`（Phase 3 已做）；或 Etherscan 該筆 tx 的 **Access List**；或 `eth_getTransactionByHash` 回傳的 `accessList`（Phase 3 廣播後會檢查）。 |
| **有 EIP-2929 預熱效果** | Access list 在執行前把條目裡的 **address / storage** 標成「暖」，可降低之後 **cold** 存取的 gas。要量化需 **對照實驗**：同一邏輯（例如同一 deploy）一筆 `access_list: "[]"`、一筆帶預測地址，比 **`receipt.gasUsed`**（差異可能不大，但非空 list 才有預熱語意）。 |

> **注意**：若已用 Phase 2 `BROADCAST=1` 發過兩筆交易，鏈上 nonce 已前進；Phase 3 每次會讀取**現有** `nonce`，無需手動對齊。

## API 對照

HTTP 路徑為 Vault 慣例：`POST ${VAULT_ADDR}/v1/blockchain/<path>`，標頭 `X-Vault-Token`。詳見專案根目錄 `README.md` 的 API 表。

## 疑難

- **403 / permission denied**：Token policy 需允許 `blockchain/wallets/...`、`blockchain/accounts/...`。
- **Phase 2 EIP-712 失敗**：確認 `SEPOLIA_RPC_URL` 正確；domain 的 `chainId` 與 **`E2E_CHAIN_ID` / state `chainId`** 及實際 RPC 鏈一致。
