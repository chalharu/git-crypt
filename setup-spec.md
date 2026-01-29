# git-crypt `setup` コマンド仕様書

## 目的
- 初期導入を簡略化し、`.gitattributes` と `git config` を一度で設定する。
- 鍵生成は **gpg で事前に実施済み**とし、`setup` は鍵ファイルのパス設定のみを行う。

## 対象コマンド
- `git-crypt setup`

## 基本方針（合意済み）
- `.gitattributes` は **先頭に挿入**し、**既存に同一行がある場合は重複させない**。
- filter は **process のみ**運用する（clean/smudge は設定しない）。
- `diff` と `merge` は **常に設定する**。
- `exe` パスは **自分自身（current_exe）**を使用し、**OSごとに書き分け**る。

---

## CLI 仕様

### 使用例
- `git-crypt setup`
- `git-crypt setup --public-key .keys/public.asc --private-key .keys/private.asc`
- `git-crypt setup --encryption-key-id 30D0EF4B71260031`
- `git-crypt setup --encryption-path-regex "^(secret|private)/"`

### オプション
- `--public-key <PATH>`  
  公開鍵ファイルパス（任意。未指定時は対話入力または既存値を利用）
- `--private-key <PATH>`  
  秘密鍵ファイルパス（任意）
- `--encryption-key-id <HEX>`  
  暗号化に使う key-id（任意）
- `--encryption-path-regex <REGEX>`  
  暗号化対象パスの正規表現（任意）
- `--filter-name <NAME>`  
  filter 名。既定値は `crypt`
- `--yes`  
  非対話モード
- `--force`  
  既存設定の上書き確認なし
- `--dry-run`  
  書き込みを行わず、変更予定のみ表示

---

## `.gitattributes` 仕様

### 挿入ルール
- **先頭に挿入**
- 既存に **同一行がある場合は追加しない**
- 既存の行順は保持

### 挿入テンプレ（固定）
- `* filter=crypt diff=crypt merge=crypt`
- `.githooks/* filter= diff= merge=`
- `.keys/* filter= diff= merge=`
- `.gitattributes filter= diff= merge=`
- `.gitignore filter= diff= merge=`
- `.gitkeep filter= diff= merge=`

---

## `git config` 設定内容

### 共通
- `filter.<name>.required=true`
- `filter.<name>.process="<EXE_CMD>" process`
- `diff.<name>.textconv="<EXE_CMD>" textconv`
- `merge.<name>.driver="<EXE_CMD>" merge %O %A %B %L %P`
- `git-crypt.public-key=<PATH>`
- `git-crypt.private-key=<PATH>`
- `git-crypt.encryption-key-id=<HEX>`（任意）
- `git-crypt.encryption-path-regex=<REGEX>`（任意）

### Windows の `<EXE_CMD>` 生成
- `$(cygpath -u <ABS_EXE> 2>/dev/null || wslpath -u <ABS_EXE> 2>/dev/null || exit 1)`

### Linux/macOS の `<EXE_CMD>` 生成
- `<ABS_EXE>`（`current_exe()` の絶対パスをそのまま使用）

---

## バリデーション

- `public-key` / `private-key` の存在チェック
- 公開鍵・秘密鍵のパース検証（`read_public_key` / `read_secret_key`）
- `.gitattributes` の同一行重複チェック
- `git config` の既存値がある場合は `--force` がないと確認

---

## 非対話モード (`--yes`)
- 未指定のオプションは既存設定値を優先
- 既存設定がなく必須値が不足する場合はエラー

---

## `--dry-run`
- 書き込みせず、変更予定の内容だけ表示する
- `.gitattributes` への追加行、`git config` へのセット値を一覧化

---

## エラー時挙動
- 鍵ファイル未存在、鍵パース失敗、`.gitattributes` 書き込み失敗時は非0終了
- `--dry-run` 時はファイルに触れない

---

## 実装備考
- `current_exe()` で exe パス取得
- OS 判定で `Windows` vs `Linux/macOS` の書式を切替
- `.gitattributes` の重複判定は **完全一致**で比較する
