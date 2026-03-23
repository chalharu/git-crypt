# git-crypt

Git の `clean` / `smudge` / `process` / `merge` ドライバで OpenPGP による暗号化・復号を行う Rust 製 CLI です。

This project is a PGP-based Git filter driver. It is distinct from AGWA's well-known `git-crypt`.

## 何ができるか

- `clean` / `smudge` / `process` フィルタで Git 入出力を暗号化・復号する
- `merge` ドライバで暗号化済みファイルを 3-way merge する
- `textconv` で差分表示用に復号する
- `pre-commit` で平文の取りこみを検出する
- `pre-auto-gc` で内部キャッシュ参照を掃除する
- `setup` で Git 設定と `.gitattributes` をまとめて初期化する

## 要件

- Git
- OpenPGP 鍵ペア
- Rust `1.85` 以上（`edition = "2024"`）

## ビルド

```bash
cargo build --release
```

## クイックスタート

### 1. 鍵を用意する

公開鍵と秘密鍵をファイルとして用意します。秘密鍵がパスフレーズ付きの場合は、実行時に `GIT_CRYPT_PASSPHRASE` 環境変数を設定してください。

```bash
export GIT_CRYPT_PASSPHRASE='your-passphrase'
```

### 2. `setup` でリポジトリを初期化する

```bash
git-crypt setup \
  --public-key /path/to/public.asc \
  --private-key /path/to/private.asc \
  --encryption-path-regex '^secret/.*' \
  --yes
```

`setup` は次をまとめて行います。

- `git config` の `git-crypt.*` 設定を書き込む
- `filter.<name>.clean` / `smudge` / `process` / `required` を書き込む
- `diff.<name>.textconv` と `merge.<name>.driver` を書き込む
- `.gitattributes` に `filter=<name> diff=<name> merge=<name>` を追加する
- `.gitattributes` / `.gitignore` / `.gitkeep` と、追跡対象の鍵ファイルは暗号化対象から除外する
- 実際に書き込む前に差分プランを表示する

差分だけ確認したい場合は `--dry-run`、対話なしで適用したい場合は `--yes`、既存設定を強制的に上書きしたい場合は `--force` を使います。

### 3. 手動設定したい場合

`setup` を使わずに手で設定する場合は、少なくとも以下が必要です。

```bash
git config git-crypt.public-key /path/to/public.asc
git config git-crypt.private-key /path/to/private.asc
git config git-crypt.encryption-path-regex '^secret/.*'
git config git-crypt.encryption-key-id '0123456789abcdef'

git config filter.crypt.clean 'git-crypt clean %f'
git config filter.crypt.smudge 'git-crypt smudge %f'
git config filter.crypt.process 'git-crypt process'
git config filter.crypt.required true
git config diff.crypt.textconv 'git-crypt textconv'
git config merge.crypt.driver 'git-crypt merge %O %A %B %L %P'
```

`.gitattributes` には次のような属性を設定します。

```gitattributes
* filter=crypt diff=crypt merge=crypt
.gitattributes filter= diff= merge=
.gitignore filter= diff= merge=
.gitkeep filter= diff= merge=
```

## Git 設定

このツールは以下の Git 設定キーを参照します。

- `git-crypt.public-key`: 公開鍵ファイルパス
- `git-crypt.private-key`: 秘密鍵ファイルパス
- `git-crypt.encryption-path-regex`: 暗号化対象パスを決める正規表現
- `git-crypt.encryption-key-id`: 使用する暗号化サブキー ID（省略時は公開鍵内の最初の暗号化サブキー）

## サブコマンド

```text
git-crypt clean <path>
git-crypt smudge <path>
git-crypt textconv <path>
git-crypt merge <base> <local> <remote> <marker_size> <path>
git-crypt pre-commit
git-crypt pre-auto-gc
git-crypt process
git-crypt setup [options]
```

### `clean`

標準入力の平文を読み、対象パスが暗号化ポリシーに一致する場合だけ暗号化して標準出力へ書きます。

### `smudge`

標準入力の暗号文を読み、復号できる場合は平文を標準出力へ書きます。暗号化対象外や対象鍵不一致のデータは素通しされます。

### `textconv`

Git の差分表示用にファイルを復号して標準出力へ書きます。

### `merge`

暗号化済みファイルを復号して 3-way merge し、結果を再暗号化してローカル側ファイルへ書き戻します。`marker_size` には `u16` に収まる数値を指定してください。

### `pre-commit`

インデックス上の暗号化対象ファイルを検査し、平文が混入していればエラーで停止します。

### `pre-auto-gc`

内部キャッシュ用の参照を整理します。

### `process`

Git filter protocol v2 用の `process` 実装です。通常はこちらを `filter.<name>.process` に設定するのが最も扱いやすいです。

### `setup`

初期設定ウィザードです。主なオプションは以下です。

- `--public-key`, `--pubkey`
- `--private-key`, `--privkey`
- `--encryption-key-id`, `--keyid`
- `--encryption-path-regex`, `--pathregex`
- `--filter-name`, `--filter`
- `--yes`, `-y`
- `--force`, `-f`
- `--dry-run`, `--dry`

## テスト

```bash
cargo test
node --test .github/hooks/postToolUse/main.test.mjs .github/scripts/*.test.mjs
./test.sh
```

## 注意事項

- パスフレーズ付き秘密鍵を使う場合は `GIT_CRYPT_PASSPHRASE` を設定してください。
- 暗号化は OpenPGP の性質上、同じ平文でも毎回同じ暗号文にはなりません。
- 本ツールのバイナリ名は一般的な別実装の `git-crypt` と衝突しやすいため、導入時は PATH 上のコマンド解決に注意してください。

## License

AGPL-3.0
