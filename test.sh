#!/bin/sh

# テストヘルパー関数

get_head() {
  if [ "$1" -le 0 ]; then
    return 0
  fi
  if [ -z "${2-}" ] || [ "${2-}" = "-" ]; then
    dd bs="$1" count=1 iflag=fullblock 2>/dev/null
  else
    dd bs="$1" count=1 if="$2" iflag=fullblock 2>/dev/null
  fi
}

# pkt-lineを生成して標準出力に書き込む
write_pkt_test() {
    PAYLOAD="$1"
    PAYLOAD_LEN=$((${#PAYLOAD} + 4))
    printf '%04x%s' "$PAYLOAD_LEN" "$PAYLOAD"
}

from_hex() {
    VAL="0x$1"
    echo "$(( VAL ))"
}

set -u

# プロジェクトのビルド
if ! CARGO_RESULT=$(cargo build --release --message-format=json); then
    echo "Build failed"
    exit 1
fi

GIT_CRYPT=$(echo "$CARGO_RESULT" | jq -r 'select(.profile.test == false and .target.kind[] == "bin") | .executable')

# 一時ディレクトリの作成とクリーンアップの設定
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT HUP INT QUIT PIPE TERM

# テスト用のGitリポジトリを作成
git init "$TMPDIR/repo"
cd "$TMPDIR/repo"
git config --local user.name "Test User"
git config --local user.email "test@example.com"

# テスト用のGPGキーを生成
mkdir "$TMPDIR/gnupg"
chmod 700 "$TMPDIR/gnupg"
export GNUPGHOME="$TMPDIR/gnupg"
gpg --batch --passphrase '' --quick-gen-key "Test User <test@example.com>"  ed25519 cert 0
FINGERPRINT=$(gpg --list-keys --with-colons | grep '^fpr:' | cut -d: -f10 | head -n 1)
gpg --batch --passphrase '' --quick-add-key "$FINGERPRINT" cv25519
KEYID=$(gpg --list-secret-keys --with-colons | grep '^ssb:' | cut -d : -f 5)

gpg --export-secret-subkeys "$FINGERPRINT" > "$TMPDIR/private.key"
gpg --export "$FINGERPRINT" > "$TMPDIR/public.key"

# git-cryptの設定を追加
git config --local git-crypt.public-key "$TMPDIR/public.key"
git config --local git-crypt.private-key "$TMPDIR/private.key"
git config --local git-crypt.encryption-key-id "$KEYID"
git config --local git-crypt.encryption-path-regex "secret/.*"

# テスト1.1: clean: 平文 -> 暗号文
echo "=== Test 1.1: clean ==="
PLAINTEXT="This is a secret file."
TEST_PATH="secret/secret.txt"
TEST_NONSECRET_PATH="nonsecret.txt"

if ! printf '%s' "$PLAINTEXT" | "$GIT_CRYPT" clean "$TEST_PATH" >"$TMPDIR/encrypted"; then
  echo "FAIL: clean returned non-zero" >&2
  exit 1
fi

if printf '%s' "$PLAINTEXT" | diff -u "$TMPDIR/encrypted" - > /dev/null; then
  echo "FAIL: clean output matches plaintext" >&2
  exit 1
fi

if ! grep -E '^-----BEGIN PGP MESSAGE-----' "$TMPDIR/encrypted" > /dev/null; then
  echo "FAIL: clean output is not a PGP message" >&2
  exit 1
fi  

echo "PASS: clean"
echo ""

# テスト1.2: clean: 平文 -> 平文 (非暗号化パス)
echo "=== Test 1.2: clean non-secret path ==="
if ! printf '%s' "$PLAINTEXT" | "$GIT_CRYPT" clean "$TEST_NONSECRET_PATH" >"$TMPDIR/non-encrypted"; then
  echo "FAIL: clean returned non-zero" >&2
  exit 1
fi

if ! (printf '%s' "$PLAINTEXT" | diff -u "$TMPDIR/non-encrypted" - > /dev/null); then
  echo "FAIL: clean output matches plaintext" >&2
  exit 1
fi

echo "PASS: clean non-secret path"
echo ""

# テスト2: smudge: 暗号文 -> 平文
# テスト1.1で生成した暗号文を使う
echo "=== Test 2: smudge ==="
# テスト2: smudge: 暗号文 -> 平文
if ! cat "$TMPDIR/encrypted" | "$GIT_CRYPT" smudge "$TEST_PATH" >"$TMPDIR/decrypted"; then
  echo "FAIL: smudge returned non-zero" >&2
  exit 1
fi

if ! (printf '%s' "$PLAINTEXT" | diff -u "$TMPDIR/decrypted" -); then
  echo "FAIL: clean/smudge round-trip mismatch" >&2
  exit 1
fi

echo "PASS: clean/smudge round-trip"
echo ""

# テスト3: textconv: 暗号文ファイル -> 平文
echo "=== Test 3: textconv ==="
cp "$TMPDIR/encrypted" "$TMPDIR/encrypted_file"

if ! "$GIT_CRYPT" textconv "$TMPDIR/encrypted_file" >"$TMPDIR/textconv_output"; then
  echo "FAIL: textconv returned non-zero" >&2
  exit 1
fi

if ! (printf '%s' "$PLAINTEXT" | diff -u "$TMPDIR/textconv_output" -); then
  echo "FAIL: textconv output mismatch" >&2
  exit 1
fi

echo "PASS: textconv"
echo ""

# テスト4.1: 競合なしマージ
echo "=== Test 4.1: No conflict merge ==="
printf "line1\nline2\nline3\nline4\nline5\n" > "$TMPDIR/base.txt"
printf "line1\nline2 modified\nline3\nline4\nline5\n" > "$TMPDIR/local.txt"
printf "line1\nline2\nline3\nline4 modified\nline5\n" > "$TMPDIR/remote.txt"

cat "$TMPDIR/base.txt" | "$GIT_CRYPT" clean "$TEST_PATH" > "$TMPDIR/base.enc"
cat "$TMPDIR/local.txt" | "$GIT_CRYPT" clean "$TEST_PATH" > "$TMPDIR/local.enc"
cat "$TMPDIR/remote.txt" | "$GIT_CRYPT" clean "$TEST_PATH" > "$TMPDIR/remote.enc"

"$GIT_CRYPT" merge "$TMPDIR/base.enc" "$TMPDIR/local.enc" "$TMPDIR/remote.enc" 0 "$TEST_PATH"
RET=$?
echo "Exit code: $RET"
if [ $RET -ne 0 ]; then
  echo "FAIL: merge returned non-zero for no-conflict case" >&2
  exit 1
fi

if ! grep -E '^-----BEGIN PGP MESSAGE-----' "$TMPDIR/local.enc" > /dev/null; then
  echo "FAIL: clean output is not a PGP message" >&2
  exit 1
fi

cat "$TMPDIR/local.enc" | "$GIT_CRYPT" smudge "$TEST_PATH" > "$TMPDIR/merged_output"

if ! grep -F 'line2 modified' "$TMPDIR/merged_output" > /dev/null; then
  echo "FAIL: merge output missing local change" >&2
  exit 1
fi

if ! grep -F 'line4 modified' "$TMPDIR/merged_output" > /dev/null; then
  echo "FAIL: merge output missing remote change" >&2
  exit 1
fi

echo "--- Merged result (encrypted) ---"
cat "$TMPDIR/local.enc"
echo "--- End of merged result (encrypted) ---"
echo "--- Merged result ---"
cat "$TMPDIR/merged_output"
echo "--- End of merged result ---"
echo ""

# テスト4.2: 競合なしマージ (非暗号化パス)
echo "=== Test 4.2: No conflict merge non-secret path ==="
printf "line1\nline2\nline3\nline4\nline5\n" > "$TMPDIR/base.txt"
printf "line1\nline2 modified\nline3\nline4\nline5\n" > "$TMPDIR/local.txt"
printf "line1\nline2\nline3\nline4 modified\nline5\n" > "$TMPDIR/remote.txt"

cat "$TMPDIR/base.txt" | "$GIT_CRYPT" clean "$TEST_PATH" > "$TMPDIR/base.enc"
cat "$TMPDIR/local.txt" | "$GIT_CRYPT" clean "$TEST_PATH" > "$TMPDIR/local.enc"
cat "$TMPDIR/remote.txt" | "$GIT_CRYPT" clean "$TEST_PATH" > "$TMPDIR/remote.enc"

"$GIT_CRYPT" merge "$TMPDIR/base.enc" "$TMPDIR/local.enc" "$TMPDIR/remote.enc" 0 "$TEST_NONSECRET_PATH"
RET=$?
echo "Exit code: $RET"
if [ $RET -ne 0 ]; then
  echo "FAIL: merge returned non-zero for no-conflict case" >&2
  exit 1
fi

if grep -E '^-----BEGIN PGP MESSAGE-----' "$TMPDIR/local.enc" > /dev/null; then
  echo "FAIL: clean output is a PGP message" >&2
  exit 1
fi

if ! grep -F 'line2 modified' "$TMPDIR/local.enc" > /dev/null; then
  echo "FAIL: merge output missing local change" >&2
  exit 1
fi

if ! grep -F 'line4 modified' "$TMPDIR/local.enc" > /dev/null; then
  echo "FAIL: merge output missing remote change" >&2
  exit 1
fi

echo "--- Merged result ---"
cat "$TMPDIR/local.enc"
echo "--- End of merged result ---"
echo ""

# テスト5: 競合ありマージ
echo "=== Test 5: Conflict merge ==="
printf "line1\noriginal\nline3\n" > "$TMPDIR/base.txt"
printf "line1\nlocal change\nline3\n" > "$TMPDIR/local.txt"
printf "line1\nremote change\nline3\n" > "$TMPDIR/remote.txt"

cat "$TMPDIR/base.txt" | "$GIT_CRYPT" clean "$TEST_PATH" > "$TMPDIR/base.enc"
cat "$TMPDIR/local.txt" | "$GIT_CRYPT" clean "$TEST_PATH" > "$TMPDIR/local.enc"
cat "$TMPDIR/remote.txt" | "$GIT_CRYPT" clean "$TEST_PATH" > "$TMPDIR/remote.enc"

"$GIT_CRYPT" merge "$TMPDIR/base.enc" "$TMPDIR/local.enc" "$TMPDIR/remote.enc" 3 "$TEST_PATH"
RET=$?
echo "Exit code: $RET (should be >0 for conflict)"
if [ $RET -eq 0 ]; then
  echo "FAIL: merge returned zero for conflict case" >&2
  echo "--- Merged result ---"
  cat "$TMPDIR/local.enc" | "$GIT_CRYPT" smudge "$TEST_PATH"
  echo "--- End of merged result ---"
  exit 1
fi

if ! grep -E '^-----BEGIN PGP MESSAGE-----' "$TMPDIR/local.enc" > /dev/null; then
  echo "FAIL: clean output is not a PGP message" >&2
  exit 1
fi

cat "$TMPDIR/local.enc" | "$GIT_CRYPT" smudge "$TEST_PATH" > "$TMPDIR/merged_output"

if ! grep -F '<<<' "$TMPDIR/merged_output" > /dev/null; then
  echo "FAIL: merge output does not contain conflict markers" >&2
  exit 1
fi

echo "--- Merged result ---"
cat "$TMPDIR/merged_output"
echo "--- End of merged result ---"
echo ""

# テスト6: pre-commitフック
echo "=== Test 6: pre-commit hook ==="
# pre-commitフックを実行してエラーが出ないことを確認
if ! "$GIT_CRYPT" pre-commit; then
  echo "FAIL: pre-commit hook returned non-zero" >&2
  exit 1
fi

# インデックスにプレーンテキストを登録する
RAW_HASH=$(printf '%s' "$PLAINTEXT" | git hash-object -w --stdin)
git update-index --add --cacheinfo 100644 "$RAW_HASH" "$TEST_PATH"

# pre-commitフックがエラーを返すことを確認
if "$GIT_CRYPT" pre-commit 2>/dev/null; then
  echo "FAIL: pre-commit hook returned zero after adding plaintext to index" >&2
  exit 1
fi

# 暗号化されたファイルのみに変更
RAW_HASH=$(git hash-object -w "$TMPDIR/encrypted")
git update-index --replace --cacheinfo 100644 "$RAW_HASH" "$TEST_PATH"

# pre-commitフックを実行してエラーが出ないことを確認
if ! "$GIT_CRYPT" pre-commit; then
  echo "FAIL: pre-commit hook returned non-zero after adding encrypted file to index" >&2
  exit 1
fi
echo "PASS: pre-commit hook"
echo ""

# テスト7: process コマンド（clean）
echo "=== Test 7: process command (clean) ==="

PROCESS_OUTPUT="$TMPDIR/process_output"

# pkt-line handshake + clean命令をシミュレート
{
    write_pkt_test "git-filter-client"
    write_pkt_test "version=2"
    printf "0000"
    
    write_pkt_test "capability=clean"
    printf "0000"

    write_pkt_test "command=clean"
    write_pkt_test "pathname=$TEST_PATH"
    printf "0000"
    
    # データペイロード
    PAYLOAD_LEN=$((${#PLAINTEXT} + 4))
    printf '%04x%s' "$PAYLOAD_LEN" "$PLAINTEXT"
    printf "0000"
} | "$GIT_CRYPT" process > "$PROCESS_OUTPUT"

if [ $? -ne 0 ]; then
    echo "FAIL: process command returned non-zero" >&2
    exit 1
fi

if ! grep -E '\-----BEGIN PGP MESSAGE-----' "$PROCESS_OUTPUT" > /dev/null; then
  echo "FAIL: process command (clean) output is not a PGP message" >&2
  exit 1
fi

# 受信データを分解
HEADER="0015git-filter-server000dversion=200000014capability=clean00000012status=success"
HEADER_LEN="${#HEADER}"
PROCESS_OUTPUT_HEADER=$(get_head "$HEADER_LEN" "$PROCESS_OUTPUT")

if [ "$PROCESS_OUTPUT_HEADER" != "$HEADER" ]; then
  echo "FAIL: process command (clean) header mismatch" >&2
  echo "Expected:"
  echo "$HEADER"
  echo "Actual:"
  echo "$PROCESS_OUTPUT_HEADER"
  exit 1
fi

TRAILER="00000000"
PROCESS_OUTPUT_TRAILER=$(tail -c 8 "$PROCESS_OUTPUT")
if [ "$PROCESS_OUTPUT_TRAILER" != "$TRAILER" ]; then
  echo "FAIL: process command (clean) trailer mismatch" >&2
  exit 1
fi

PROCESS_OUTPUT_PAYLOAD=$(tail -c +$(($HEADER_LEN + 5)) "$PROCESS_OUTPUT")
PROCESS_OUTPUT_PAYLOAD_LENGTH_HEX=$(echo "$PROCESS_OUTPUT_PAYLOAD" | get_head 4)
PROCESS_OUTPUT_PAYLOAD_LENGTH=$(from_hex $PROCESS_OUTPUT_PAYLOAD_LENGTH_HEX)
PROCESS_OUTPUT_PAYLOAD_TOTAL_LENGTH=$(echo "$PROCESS_OUTPUT_PAYLOAD" | wc -c)
PROCESS_OUTPUT_PAYLOAD_TOTAL_LENGTH=$(( $PROCESS_OUTPUT_PAYLOAD_TOTAL_LENGTH - 9 ))

if [ $PROCESS_OUTPUT_PAYLOAD_TOTAL_LENGTH -ne $PROCESS_OUTPUT_PAYLOAD_LENGTH ]; then
  echo "FAIL: process command (clean) payload length mismatch" >&2
  exit 1
fi

PROCESS_OUTPUT_PAYLOAD_BODY=$(echo "$PROCESS_OUTPUT_PAYLOAD" | tail -c +5 | get_head "$((PROCESS_OUTPUT_PAYLOAD_TOTAL_LENGTH - 4))")

if !(echo "$PROCESS_OUTPUT_PAYLOAD_BODY" | diff -u "$TMPDIR/encrypted" -); then
  echo "FAIL: process command (clean) payload mismatch" >&2
  exit 1
fi

echo "PASS: process command (clean)"
echo ""

# テスト8: process コマンド（smudge）
echo "=== Test 8: process command (smudge) ==="
PROCESS_OUTPUT="$TMPDIR/process_output_smudge"
# pkt-line handshake + smudge命令をシミュレート
{
    write_pkt_test "git-filter-client"
    write_pkt_test "version=2"
    printf "0000"
    
    write_pkt_test "capability=smudge"
    printf "0000"

    write_pkt_test "command=smudge"
    write_pkt_test "pathname=$TEST_PATH"
    printf "0000"
    
    # データペイロード
    PAYLOAD_LEN=$(($(wc -c < "$TMPDIR/encrypted") + 4))
    printf '%04x' "$PAYLOAD_LEN"
    cat "$TMPDIR/encrypted"
    printf "0000"
} | "$GIT_CRYPT" process > "$PROCESS_OUTPUT"

if [ $? -ne 0 ]; then
    echo "FAIL: process command (smudge) returned non-zero" >&2
    exit 1
fi

# 受信データを分解
HEADER="0015git-filter-server000dversion=200000015capability=smudge00000012status=success"
HEADER_LEN="${#HEADER}"
PROCESS_OUTPUT_HEADER=$(get_head "$HEADER_LEN" "$PROCESS_OUTPUT")

if [ "$PROCESS_OUTPUT_HEADER" != "$HEADER" ]; then
  echo "FAIL: process command (smudge) header mismatch" >&2
  exit 1
fi

TRAILER="00000000"
PROCESS_OUTPUT_TRAILER=$(tail -c 8 "$PROCESS_OUTPUT")
if [ "$PROCESS_OUTPUT_TRAILER" != "$TRAILER" ]; then
  echo "FAIL: process command (smudge) trailer mismatch" >&2
  exit 1
fi

PROCESS_OUTPUT_PAYLOAD=$(tail -c +$(($HEADER_LEN + 5)) "$PROCESS_OUTPUT")
PROCESS_OUTPUT_PAYLOAD_LENGTH_HEX=$(echo "$PROCESS_OUTPUT_PAYLOAD" | get_head 4)
PROCESS_OUTPUT_PAYLOAD_LENGTH=$(from_hex $PROCESS_OUTPUT_PAYLOAD_LENGTH_HEX)
PROCESS_OUTPUT_PAYLOAD_TOTAL_LENGTH=$(echo "$PROCESS_OUTPUT_PAYLOAD" | wc -c)
PROCESS_OUTPUT_PAYLOAD_TOTAL_LENGTH=$(( $PROCESS_OUTPUT_PAYLOAD_TOTAL_LENGTH - 9 ))

if [ $PROCESS_OUTPUT_PAYLOAD_TOTAL_LENGTH -ne $PROCESS_OUTPUT_PAYLOAD_LENGTH ]; then
  echo "FAIL: process command (smudge) payload length mismatch" >&2
  exit 1
fi

PROCESS_OUTPUT_PAYLOAD_BODY=$(echo "$PROCESS_OUTPUT_PAYLOAD" | tail -c +5 | get_head "$((PROCESS_OUTPUT_PAYLOAD_TOTAL_LENGTH - 4))")

if ! (printf '%s' "$PROCESS_OUTPUT_PAYLOAD_BODY" | diff -u "$TMPDIR/decrypted" -); then
  echo "FAIL: process command (smudge) payload mismatch" >&2
  exit 1
fi

echo "PASS: process command (smudge)"
echo ""

# テスト9: pre-auto-gcフック
echo "=== Test 9: pre-auto-gc hook ==="
# pre-auto-gcフックを実行してエラーが出ないことを確認
if ! "$GIT_CRYPT" pre-auto-gc; then
  echo "FAIL: pre-auto-gc hook returned non-zero" >&2
  exit 1
fi
echo "PASS: pre-auto-gc hook"
echo ""
