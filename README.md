# git-crypt

Gitのclean/smudge・mergeドライバでPGP暗号化/復号を行うツール。

## Build
```
cargo build --release
```

## Config
```
git config git-crypt.public-key /path/to/public.asc
git config git-crypt.private-key /path/to/private.asc
git config git-crypt.encryption-path-regex '.*\.secret$'
git config git-crypt.encryption-key-id '0123456789abcdef'
```

## Usage
```
git-crypt clean <path>
git-crypt smudge <path>
git-crypt textconv <path>
git-crypt merge <base> <local> <remote> <marker_size> <path>
git-crypt pre-commit
git-crypt pre-auto-gc
git-crypt process
```

## License
AGPL-3.0
