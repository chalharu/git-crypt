#!/bin/sh

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

# テスト1: clean: 平文 -> 暗号文
echo "=== Test 1: clean ==="
PLAINTEXT="This is a secret file."
TEST_PATH="secret/secret.txt"

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

# テスト2: smudge: 暗号文 -> 平文
# テスト１で生成した暗号文を使う
echo "=== Test 2: smudge ==="
cp "$TMPDIR/encrypted" "$TMPDIR/encrypted_file"
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


# テスト4: 競合なしマージ
echo "=== Test 4: No conflict merge ==="
printf "line1\nline2\nline3\nline4\nline5\n" > "$TMPDIR/base.txt"
printf "line1\nline2 modified\nline3\nline4\nline5\n" > "$TMPDIR/local.txt"
printf "line1\nline2\nline3\nline4 modified\nline5\n" > "$TMPDIR/remote.txt"

cat "$TMPDIR/base.txt" | "$GIT_CRYPT" clean "$TEST_PATH" > "$TMPDIR/base.enc"
cat "$TMPDIR/local.txt" | "$GIT_CRYPT" clean "$TEST_PATH" > "$TMPDIR/local.enc"
cat "$TMPDIR/remote.txt" | "$GIT_CRYPT" clean "$TEST_PATH" > "$TMPDIR/remote.enc"

"$GIT_CRYPT" merge "$TMPDIR/base.enc" "$TMPDIR/local.enc" "$TMPDIR/remote.enc" 0 "$TMPDIR/merged.enc"
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

cat "$TMPDIR/merged.enc" | "$GIT_CRYPT" smudge "$TMPDIR/merged.enc" > "$TMPDIR/merged_output"

if ! grep -F 'line2 modified' "$TMPDIR/merged_output" > /dev/null; then
  echo "FAIL: merge output missing local change" >&2
  exit 1
fi

if ! grep -F 'line4 modified' "$TMPDIR/merged_output" > /dev/null; then
  echo "FAIL: merge output missing remote change" >&2
  exit 1
fi

echo "--- Merged result ---"
cat "$TMPDIR/merged_output"
echo "--- End of merged result ---"
echo ""
