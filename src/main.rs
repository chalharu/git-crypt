use std::{
    collections::{HashMap, HashSet},
    env::current_dir,
    ffi::{OsStr, OsString},
    fs,
    io::{
        self, BufReader, BufWriter, ErrorKind, Read as _, Seek, StdinLock, StdoutLock, Write as _,
    },
    path::{Path, PathBuf},
};

use clap::{Parser, Subcommand};
use git2::{
    Delta, DiffOptions, MergeFileInput, MergeFileOptions, ObjectType, TreeWalkMode, TreeWalkResult,
};
use pgp::{
    composed::{
        ArmorOptions, DecryptionOptions, Deserializable as _, Esk, Message, MessageBuilder,
        SignedPublicKey, SignedSecretKey, TheRing,
    },
    crypto::sym::SymmetricKeyAlgorithm,
    types::{CompressionAlgorithm, KeyDetails, PublicKeyTrait},
};
use regex::bytes::Regex;

#[derive(Parser, Clone, Debug)]
struct Cli {
    /// デバッグトレース出力を有効化
    #[arg(short, long)]
    debug: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Clone, Debug)]
pub enum Commands {
    /// git cleanフィルタ用コマンド
    Clean {
        /// ファイルパス
        #[arg(index = 1)]
        file_path: OsString,
    },
    /// git smudgeフィルタ用コマンド
    Smudge {
        /// ファイルパス
        #[arg(index = 1)]
        file_path: OsString,
    },
    /// git textconvフィルタ用コマンド
    Textconv {
        /// ファイルパス
        #[arg(index = 1)]
        file_path: PathBuf,
    },
    /// git mergeドライバ用コマンド
    Merge {
        /// ベースファイルパス
        #[arg(index = 1)]
        base: PathBuf,
        /// ローカルファイルパス
        #[arg(index = 2)]
        local: PathBuf,
        /// リモートファイルパス
        #[arg(index = 3)]
        remote: PathBuf,
        /// マーカーサイズ
        #[arg(index = 4)]
        marker_size: String,
        /// ファイルパス
        #[arg(index = 5)]
        file_path: OsString,
    },
    /// git pre-commitフック用コマンド
    PreCommit,
    /// git pre-auto-gcフック用コマンド
    PreAutoGc,
    /// git clean/smudgeのprocessコマンド
    Process,
}

trait ToPath<'a> {
    fn to_path(self) -> Option<&'a Path>;
    fn as_bytes(&self) -> &'a [u8];
}

impl<'a> ToPath<'a> for &'a [u8] {
    fn to_path(self) -> Option<&'a Path> {
        #[cfg(unix)]
        let path: Result<_, std::convert::Infallible> =
            Ok(<OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(self));
        #[cfg(not(unix))]
        let path = str::from_utf8(self);
        match path {
            Ok(s) => Some(Path::new(s)),
            Err(_) => None,
        }
    }

    fn as_bytes(&self) -> &'a [u8] {
        self
    }
}

impl<'a> ToPath<'a> for &'a OsStr {
    fn to_path(self) -> Option<&'a Path> {
        Some(Path::new(self))
    }

    fn as_bytes(&self) -> &'a [u8] {
        self.as_encoded_bytes()
    }
}

fn main() {
    let cli = Cli::parse();

    if cli.debug {
        if let Err(e) = stderrlog::new()
            .module(module_path!())
            .verbosity(3)
            .timestamp(stderrlog::Timestamp::Second)
            .init()
        {
            eprintln!("Failed to initialize logging: {}", e);
            std::process::exit(1);
        }
        log::debug!("Debug mode is enabled");
    } else {
        if let Err(e) = stderrlog::new()
            .module(module_path!())
            .verbosity(0)
            .timestamp(stderrlog::Timestamp::Off)
            .show_level(false)
            .init()
        {
            eprintln!("Failed to initialize logging: {}", e);
            std::process::exit(1);
        }
    }

    match cli.command {
        Commands::Clean { file_path } => {
            if let Err(e) = clean(&file_path) {
                log::error!("Error during clean: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Smudge { file_path } => {
            if let Err(e) = smudge(&file_path) {
                log::error!("Error during smudge: {:?}", e);
                std::process::exit(1);
            }
        }
        Commands::Textconv { file_path } => {
            if let Err(e) = textconv(&file_path) {
                log::error!("Error during textconv: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Merge {
            base,
            local,
            remote,
            marker_size,
            file_path,
        } => match merge(&base, &local, &remote, marker_size.parse().ok(), &file_path) {
            Ok(is_automergeable) => std::process::exit(if is_automergeable { 0 } else { 1 }),
            Err(e) => {
                log::error!("Error during merge: {}", e);
                std::process::exit(2);
            }
        },
        Commands::PreCommit => {
            if let Err(e) = pre_commit() {
                log::error!("Pre-commit hook failed: {}", e);
                std::process::exit(1);
            }
        }
        Commands::PreAutoGc => {
            if let Err(e) = pre_auto_gc() {
                log::error!("Pre-auto-gc hook failed: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Process => {
            let mut processor = match PktLineProcess::new() {
                Ok(p) => p,
                Err(e) => {
                    log::error!("Error during initialization: {}", e);
                    std::process::exit(1);
                }
            };

            if let Err(e) = processor.process() {
                log::error!("Error during process: {}", e);
                std::process::exit(1);
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("Failed to load git configuration")]
    GitConfig(#[from] git2::Error),
    #[error("IO error occurred")]
    Io(#[from] std::io::Error),
    #[error("PGP error occurred")]
    Pgp(#[from] pgp::errors::Error),
    #[error("Encryption subkey is not valid for encryption")]
    InvalidEncryptionSubkey,
    #[error("Hex decoding error")]
    HexDecoding(#[from] hex::FromHexError),
    #[error("Regex error occurred")]
    Regex(#[from] regex::Error),
    #[error("File '{0}' is not encrypted. Clean filter may not be working.")]
    NotEncrypted(PathBuf),
    #[error("Invalid handshake payload: {0:?}")]
    InvalidHandshakePayload(String),
    #[error("Unexpected end of file")]
    UnexpectedEof,
    #[error("Invalid version")]
    InvalidVersion,
    #[error("Pathname is missing in the command")]
    PathnameIsMissing,
    #[error("Invalid packet length")]
    InvalidPacketLength,
    #[error("Invalid packet UTF-8: {0}")]
    InvalidPacketUtf8(#[from] std::string::FromUtf8Error),
}

#[derive(Debug)]
struct KeyPair {
    public_key: SignedPublicKey,
    private_key: SignedSecretKey,
}

impl TryFrom<&GitConfig> for KeyPair {
    type Error = Error;
    fn try_from(config: &GitConfig) -> Result<Self, Error> {
        let public_key = read_public_key(&fs::read(&config.public_key)?)?;
        log::debug!("Loaded public key: {}", public_key.fingerprint());
        let private_key = read_secret_key(&fs::read(&config.private_key)?)?;
        log::debug!("Loaded private key: {}", private_key.fingerprint());
        Ok(KeyPair {
            public_key,
            private_key,
        })
    }
}

/// Parse private key from either armored or binary format
fn read_secret_key(input: &[u8]) -> Result<SignedSecretKey, Error> {
    let (key, _headers) = SignedSecretKey::from_reader_single(input)?;

    // Check that the binding self-signatures for each component are valid
    key.verify()?;

    Ok(key)
}

/// Parse public key from either armored or binary format
fn read_public_key(input: &[u8]) -> Result<SignedPublicKey, Error> {
    let (cert, _headers) = SignedPublicKey::from_reader_single(input)?;

    // Check that the binding self-signatures for each component are valid
    cert.verify()?;

    Ok(cert)
}

#[derive(Debug)]
struct GitConfig {
    public_key: String,
    private_key: String,
    encryption_path_regex: Option<String>,
    encryption_key_id: Option<String>,

    // flyweight pattern
    encryption_path_regex_instance: Option<Regex>,
    encryption_key_id_vec: Option<Vec<u8>>,
}

impl GitConfig {
    fn should_encrypt_file_path(&mut self, path: &[u8]) -> Result<bool, Error> {
        if self.encryption_path_regex_instance.is_none() {
            if let Some(ref regex_str) = self.encryption_path_regex {
                let compiled_regex = Regex::new(regex_str)?;
                self.encryption_path_regex_instance = Some(compiled_regex);
            } else {
                // 正規表現が設定されていない場合は常にtrueを返す = すべてのファイルを暗号化対象とする
                return Ok(true);
            }
        }
        // ここまで来たら正規表現が存在するのでunwrapして使用
        let regex = self.encryption_path_regex_instance.as_ref().unwrap();
        Ok(regex.is_match(path))
    }

    fn is_encrypted_for_configured_key(&mut self, message: &Message) -> Result<bool, Error> {
        if let Some(key_id) = self.encryption_key_id()? {
            if let Message::Encrypted { esk, .. } = message {
                for e in esk.iter() {
                    if let Esk::PublicKeyEncryptedSessionKey(pubkey) = e
                        && let Ok(id) = pubkey.id()
                        && id.as_ref().iter().eq(key_id.iter())
                    {
                        // 指定されたキーIDに一致する公開鍵で暗号化されている場合、そのまま出力
                        return Ok(true);
                    }
                }
            }
        } else {
            // キーIDが指定されていない場合、すでに暗号化されているならそのまま出力
            return Ok(message.is_encrypted());
        }
        Ok(false)
    }

    fn encryption_key_id(&mut self) -> Result<Option<&[u8]>, Error> {
        if self.encryption_key_id_vec.is_none() {
            if let Some(ref encryption_key_id) = self.encryption_key_id {
                let encryption_key_id_vec = hex::decode(encryption_key_id)?;
                self.encryption_key_id_vec = Some(encryption_key_id_vec);
            } else {
                // encryption_key_idが設定されていない場合はNoneを返す
                return Ok(None);
            }
        }
        Ok(self.encryption_key_id_vec.as_deref())
    }
}

// gitの設定を読み込む関数
fn load_git_config(repo: &GitRepository) -> Result<GitConfig, Error> {
    let config = repo.repo.config()?;

    let public_key = config.get_string("git-crypt.public-key")?;
    let private_key = config.get_string("git-crypt.private-key")?;
    let encryption_path_regex = config.get_string("git-crypt.encryption-path-regex").ok();
    let encryption_key_id = config.get_string("git-crypt.encryption-key-id").ok();

    Ok(GitConfig {
        public_key,
        private_key,
        encryption_path_regex,
        encryption_key_id,
        encryption_path_regex_instance: None,
        encryption_key_id_vec: None,
    })
}

struct GitRepository {
    repo: git2::Repository,
}

impl GitRepository {
    fn new() -> Result<Self, Error> {
        let repo = git2::Repository::open(current_dir()?)?;
        Ok(GitRepository { repo })
    }
}

fn clean(path: &OsStr) -> Result<(), Error> {
    let mut repo = GitRepository::new()?;

    let mut config = load_git_config(&repo)?;
    let keypair = KeyPair::try_from(&config)?;

    let mut data = Vec::new();
    std::io::stdin().lock().read_to_end(&mut data)?;

    let encrypted = encrypt(&keypair, &mut config, &data, path, &mut repo)?;
    std::io::stdout().write_all(&encrypted)?;

    Ok(())
}

fn smudge(path: &OsStr) -> Result<(), Error> {
    let mut repo = GitRepository::new()?;

    let mut config = load_git_config(&repo)?;
    let keypair = KeyPair::try_from(&config)?;

    let mut data = Vec::new();
    std::io::stdin().lock().read_to_end(&mut data)?;

    let decrypted = decrypt(
        &keypair,
        &data,
        &mut repo,
        path.as_encoded_bytes(),
        &mut config,
    )?;
    std::io::stdout().write_all(&decrypted)?;

    Ok(())
}

fn encrypt<'a, T: 'a + ToPath<'a>>(
    key_pair: &KeyPair,
    config: &mut GitConfig,
    data: &[u8],
    path: T,
    repo: &mut GitRepository,
) -> Result<Vec<u8>, Error> {
    if !config.should_encrypt_file_path(path.as_bytes())? {
        // 暗号化対象外のファイルの場合はそのまま出力
        return Ok(data.to_vec());
    }
    // git hash-objectとして登録
    let oid = repo.repo.blob(data)?;

    let encrypt_ref = format!("refs/crypt-cache/encrypt/{}", oid);
    if let Ok(encrypt_obj) = repo.repo.find_reference(&encrypt_ref)
        && let Some(ref_target) = encrypt_obj.target()
    {
        // encrypt_refが存在する = このマシンで暗号化したことがある
        match repo.repo.find_blob(ref_target) {
            Ok(encrypt_obj) => return Ok(encrypt_obj.content().to_vec()),
            Err(e) if e.code() != git2::ErrorCode::NotFound => return Err(e.into()),
            _ => {}
        };
    };

    if let Ok((message, _)) = Message::from_armor(data)
        && config.is_encrypted_for_configured_key(&message)?
    {
        // すでに指定されたキーIDに一致する公開鍵で暗号化されている場合、そのまま出力
        return Ok(data.to_vec());
    }

    // インデックスの内容を取得して復号化を試みる
    if let Some(path) = path.to_path()
        && let Some(index_entry) = repo.repo.index()?.get_path(Path::new(path), 0)
        && let Ok(blob) = repo.repo.find_blob(index_entry.id)
        && let Ok((message, _)) = Message::from_armor(blob.content())
        && let Ok(decrypted_data) = message.decrypt(&"".into(), &key_pair.private_key)
    {
        // インデックスの内容を復号化できた場合、復号化した内容と同一ならば再暗号化せずにそのまま出力
        if let Some(mut decompressed_data) = if decrypted_data.is_compressed() {
            decrypted_data.decompress().ok()
        } else {
            Some(decrypted_data)
        } && let Ok(decompressed_bytes) = decompressed_data.as_data_vec()
            && decompressed_bytes.iter().eq(data.iter())
        {
            // キャッシュ化
            let raw_ref = format!("refs/crypt-cache/decrypt/{}", index_entry.id);

            // 失敗しても無視
            let _ = repo
                .repo
                .reference(&encrypt_ref, index_entry.id, true, "Update encrypt cache");
            let _ = repo
                .repo
                .reference(&raw_ref, oid, true, "Update decrypt cache")?;

            return Ok(blob.content().to_vec());
        }
    }

    // ファイルを暗号化して出力
    let encryption_subkey = if let Some(key_id) = config.encryption_key_id()? {
        // 指定されたキーIDに一致するサブキーを探す
        key_pair.public_key.public_subkeys.iter().find(|subkey| {
            subkey.is_encryption_key()
                && subkey
                    .as_unsigned()
                    .key_id()
                    .as_ref()
                    .iter()
                    .eq(key_id.iter())
        })
    } else {
        key_pair
            .public_key
            .public_subkeys
            .iter()
            .find(|subkey| subkey.is_encryption_key())
    };
    let encryption_subkey = match encryption_subkey {
        Some(key) => key,
        None => return Err(Error::InvalidEncryptionSubkey),
    };

    let mut builder = MessageBuilder::from_bytes("", data.to_vec())
        .seipd_v1(rand::thread_rng(), SymmetricKeyAlgorithm::AES256);
    builder.compression(CompressionAlgorithm::ZLIB);
    builder.encrypt_to_key(rand::thread_rng(), &encryption_subkey)?;

    let encrypted = builder.to_armored_string(rand::thread_rng(), ArmorOptions::default())?;

    // キャッシュ化
    if let Ok(encrypt_obj_oid) = repo.repo.blob(encrypted.as_bytes()) {
        // hash-objectの書き込みに成功した場合のみrefを更新
        // 失敗した場合でも出力自体は成功しているため、処理は継続
        let raw_ref = format!("refs/crypt-cache/decrypt/{}", encrypt_obj_oid);
        let _ = repo
            .repo
            .reference(&encrypt_ref, encrypt_obj_oid, true, "Update encrypt cache");
        let _ = repo
            .repo
            .reference(&raw_ref, oid, true, "Update decrypt cache");
    }

    Ok(encrypted.as_bytes().to_vec())
}

fn decrypt(
    key_pair: &KeyPair,
    data: &[u8],
    repo: &mut GitRepository,
    path: &[u8],
    config: &mut GitConfig,
) -> Result<Vec<u8>, Error> {
    let message = match Message::from_armor(data) {
        Ok((msg, _)) => msg,
        Err(e) => {
            // パケットが不正 = 暗号化されていない場合はそのまま出力
            // 本来は平文と破損を区別したいが、現状では区別できないためそのまま出力
            if config.should_encrypt_file_path(path).unwrap_or(false) {
                log::error!("Not a valid PGP message ({:?}), outputting raw data", e);
            }
            return Ok(data.to_vec());
        }
    };
    if !message.is_encrypted() {
        // 暗号化されていない場合はそのまま出力
        return Ok(data.to_vec());
    }
    if !config.is_encrypted_for_configured_key(&message)? {
        // 指定されたキーIDに一致する公開鍵で暗号化されていない場合はそのまま出力
        return Ok(data.to_vec());
    }

    // キャッシュ確認
    let oid = repo.repo.blob(data)?;
    let decrypt_ref = format!("refs/crypt-cache/decrypt/{}", oid);
    if let Ok(decrypt_obj) = repo.repo.find_reference(&decrypt_ref)
        && let Some(ref_target) = decrypt_obj.target()
        && let Ok(decrypt_blob) = repo.repo.find_blob(ref_target)
    {
        // キャッシュヒット
        return Ok(decrypt_blob.content().to_vec());
    }

    // 復号化処理
    let decrypt_options = DecryptionOptions::new().enable_gnupg_aead().enable_legacy();
    let password = "".into();
    let ring = TheRing {
        secret_keys: vec![&key_pair.private_key],
        key_passwords: vec![&password],
        decrypt_options,
        ..Default::default()
    };
    let (decrypted_message, _) = match message.decrypt_the_ring(ring, true) {
        Ok(msg) => msg,
        Err(pgp::errors::Error::MissingKey) => {
            // 復号化キーが見つからない場合はそのまま出力
            return Ok(data.to_vec());
        }
        Err(e) => return Err(e.into()),
    };
    let mut decompressed_data = if decrypted_message.is_compressed() {
        decrypted_message.decompress()?
    } else {
        decrypted_message
    };
    let decrypted_bytes = decompressed_data.as_data_vec()?;

    // キャッシュ化
    if let Ok(decrypt_obj_oid) = repo.repo.blob(decrypted_bytes.as_slice()) {
        let encrypt_ref = format!("refs/crypt-cache/encrypt/{}", decrypt_obj_oid);
        let _ = repo
            .repo
            .reference(&encrypt_ref, oid, true, "Update encrypt cache");
        let _ = repo
            .repo
            .reference(&decrypt_ref, decrypt_obj_oid, true, "Update decrypt cache");
    }
    Ok(decrypted_bytes)
}

fn textconv(path: &Path) -> Result<(), Error> {
    let mut repo = GitRepository::new()?;

    let mut config = load_git_config(&repo)?;
    let keypair = KeyPair::try_from(&config)?;

    let data = fs::read(path)?;

    let decrypted = decrypt(
        &keypair,
        &data,
        &mut repo,
        path.as_os_str().as_encoded_bytes(),
        &mut config,
    )?;
    std::io::stdout().write_all(&decrypted)?;

    Ok(())
}

fn pre_commit() -> Result<(), Error> {
    let repo = GitRepository::new()?;
    let mut config = load_git_config(&repo)?;

    let diff = repo.repo.diff_tree_to_index(
        repo.repo
            .head()
            .ok()
            .and_then(|head_ref| head_ref.target())
            .and_then(|head| repo.repo.find_commit(head).ok())
            .and_then(|head| head.tree().ok())
            .as_ref(),
        None,
        Some(
            DiffOptions::default()
                .ignore_filemode(true)
                .ignore_case(true),
        ),
    )?;

    for d in diff.deltas().filter(|d| {
        matches!(
            d.status(),
            Delta::Added | Delta::Modified | Delta::Renamed | Delta::Copied
        )
    }) {
        let oid = d.new_file().id();
        if let Some(file_path) = d.new_file().path()
            && config.should_encrypt_file_path(file_path.as_os_str().as_encoded_bytes())?
        {
            let blob = repo.repo.find_blob(oid)?;
            let data = blob.content();

            if let Ok((message, _)) = Message::from_armor(data)
                && config.is_encrypted_for_configured_key(&message)?
            {
                continue; // 暗号化されているので次へ
            }
            return Err(Error::NotEncrypted(file_path.to_path_buf()));
        }
    }
    Ok(())
}

fn pre_auto_gc() -> Result<(), Error> {
    let repo = GitRepository::new()?;

    let mut crypt_cache_paths = HashMap::new();
    let mut weak_map = HashMap::new();

    // 既存のcrypt-cache参照を取得
    for reference in repo.repo.references_glob("refs/crypt-cache/*")? {
        let reference = reference?;
        if let Some(name) = reference.name() {
            let parts: Vec<&str> = name.split('/').collect();
            // refs/crypt-cache/{type}/{oid}
            if parts.len() == 4
                && let Some(target_oid) = reference.target()
            {
                let oid_str = parts[3];
                let key = crypt_cache_paths.len();
                crypt_cache_paths.insert(key, name.to_string());
                weak_map
                    .entry(oid_str.to_string())
                    .or_insert(HashSet::new())
                    .insert(key);
                weak_map
                    .entry(target_oid.to_string())
                    .or_insert(HashSet::new())
                    .insert(key);
            }
        }
    }

    let mut revwalk = repo.repo.revwalk()?;

    // 参照をすべて追加
    for reference in repo.repo.references()? {
        let reference = reference?;
        if let Some(name) = reference.name()
            && !name.starts_with("refs/crypt-cache")
        {
            revwalk.push_ref(name)?;
        }
    }

    // 利用しているオブジェクトを確認し、削除してはならないcrypt-cache参照を削除
    for commit_oid in revwalk {
        let commit_oid = commit_oid?;
        let commit = repo.repo.find_commit(commit_oid)?;
        let tree = commit.tree()?;
        tree.walk(TreeWalkMode::PreOrder, |_, entry| {
            if entry.kind() == Some(ObjectType::Blob)
                && let Some(keys) = weak_map.remove(entry.id().to_string().as_str())
            {
                for key in keys {
                    crypt_cache_paths.remove(&key);
                }
            }
            TreeWalkResult::Ok
        })?;
    }

    // 残ったcrypt-cache参照を削除
    for (_, ref_name) in crypt_cache_paths {
        if let Ok(mut reference) = repo.repo.find_reference(&ref_name) {
            log::error!("Deleting unused reference: {}", ref_name);
            // エラーが発生しても無視
            let _ = reference.delete();
        }
    }

    Ok(())
}

fn merge(
    base: &Path,
    local: &Path,
    remote: &Path,
    marker_size: Option<usize>,
    file_path: &OsStr,
) -> Result<bool, Error> {
    let mut repo = GitRepository::new()?;
    let mut config = load_git_config(&repo)?;
    let keypair = KeyPair::try_from(&config)?;

    let base_data = fs::read(base)?;
    let base_data = decrypt(
        &keypair,
        &base_data,
        &mut repo,
        base.as_os_str().as_encoded_bytes(),
        &mut config,
    )?;
    let mut base_obj = MergeFileInput::new();
    base_obj.content(&base_data);
    base_obj.path(base);

    let mut local_file = fs::OpenOptions::new().write(true).read(true).open(local)?;
    let mut local_data = Vec::new();
    local_file.read_to_end(&mut local_data)?;
    let local_data = decrypt(
        &keypair,
        &local_data,
        &mut repo,
        local.as_os_str().as_encoded_bytes(),
        &mut config,
    )?;
    let mut local_obj = MergeFileInput::new();
    local_obj.content(&local_data);
    local_obj.path(local);

    let remote_data = fs::read(remote)?;
    let remote_data = decrypt(
        &keypair,
        &remote_data,
        &mut repo,
        remote.as_os_str().as_encoded_bytes(),
        &mut config,
    )?;
    let mut remote_obj = MergeFileInput::new();
    remote_obj.content(&remote_data);
    remote_obj.path(remote);

    // ここで3-wayマージを実行する
    let mut file_opts = MergeFileOptions::new();
    if let Some(marker_size) = marker_size {
        file_opts.marker_size(marker_size as u16);
    }

    let result = git2::merge_file(&base_obj, &local_obj, &remote_obj, Some(&mut file_opts))?;
    let encrypted = encrypt(
        &keypair,
        &mut config,
        result.content(),
        file_path,
        &mut repo,
    )?;

    local_file.seek(io::SeekFrom::Start(0))?; // ファイルポインタを先頭に戻す
    local_file.set_len(0)?; // ファイルを空にする
    local_file.write_all(&encrypted)?;
    local_file.flush()?;

    Ok(result.is_automergeable())
}

struct PktLineIO {
    reader: BufReader<StdinLock<'static>>,
    writer: BufWriter<StdoutLock<'static>>,
}

enum PktLineReadResult {
    Packet(Vec<u8>),
    Flush,
    Eof,
}

impl PktLineReadResult {
    fn without_eof(self) -> Result<Option<Vec<u8>>, Error> {
        match self {
            PktLineReadResult::Packet(data) => Ok(Some(data)),
            PktLineReadResult::Flush => Ok(None),
            PktLineReadResult::Eof => Err(Error::UnexpectedEof),
        }
    }
}

enum PktLineTextResult {
    Packet(String),
    Flush,
    Eof,
}

impl TryFrom<PktLineReadResult> for PktLineTextResult {
    type Error = Error;

    fn try_from(value: PktLineReadResult) -> Result<Self, Self::Error> {
        match value {
            PktLineReadResult::Packet(data) => {
                let mut text = String::from_utf8(data)?;
                if text.ends_with('\n') {
                    text.truncate(text.len() - 1);
                }
                Ok(PktLineTextResult::Packet(text))
            }
            PktLineReadResult::Flush => Ok(PktLineTextResult::Flush),
            PktLineReadResult::Eof => Ok(PktLineTextResult::Eof),
        }
    }
}

impl PktLineTextResult {
    fn without_eof(self) -> Result<Option<String>, Error> {
        match self {
            PktLineTextResult::Packet(data) => Ok(Some(data)),
            PktLineTextResult::Flush => Ok(None),
            PktLineTextResult::Eof => Err(Error::UnexpectedEof),
        }
    }

    fn into_packet(self) -> Result<String, Error> {
        match self {
            PktLineTextResult::Packet(data) => Ok(data),
            _ => Err(Error::UnexpectedEof),
        }
    }
}

impl PktLineIO {
    fn new() -> Self {
        let reader = std::io::stdin().lock();
        let writer = std::io::stdout().lock();

        let bufreader = BufReader::new(reader);
        let bufwriter = BufWriter::new(writer);

        PktLineIO {
            reader: bufreader,
            writer: bufwriter,
        }
    }

    fn write_pkt_line(&mut self, data: &[u8]) -> Result<(), Error> {
        let length = data.len() + 4; // 4 bytes for length prefix
        let length_str = format!("{:04x}", length);
        log::debug!(
            "Writing pkt-line: {}",
            data[..50.min(data.len())].escape_ascii()
        );
        self.writer.write_all(length_str.as_bytes())?;
        self.writer.write_all(data)?;
        Ok(())
    }

    fn write_pkt_string(&mut self, data: &str) -> Result<(), Error> {
        if data.ends_with('\n') {
            self.write_pkt_line(data.as_bytes())
        } else {
            let mut line = data.to_string();
            line.push('\n');
            self.write_pkt_line(line.as_bytes())
        }
    }

    fn write_pkt_content(&mut self, data: &[u8]) -> Result<(), Error> {
        self.write_pkt_string("status=success")?;
        self.write_flush_pkt()?;

        const LARGE_PACKET_MAX: usize = 65520;
        let mut offset = 0;
        while offset < data.len() {
            let chunk_size = std::cmp::min(LARGE_PACKET_MAX - 4, data.len() - offset);
            self.write_pkt_line(&data[offset..offset + chunk_size])?;
            offset += chunk_size;
        }
        self.write_flush_pkt()?;
        Ok(())
    }

    fn write_flush_pkt(&mut self) -> Result<(), Error> {
        log::debug!("Writing pkt-line: 0000 (flush)");
        self.writer.write_all(b"0000")?;
        self.writer.flush()?;
        Ok(())
    }

    fn read_pkt_line(&mut self) -> Result<PktLineReadResult, Error> {
        let mut length_buf = [0u8; 4];
        if let Err(e) = self.reader.read_exact(&mut length_buf) {
            if e.kind() == ErrorKind::UnexpectedEof {
                return Ok(PktLineReadResult::Eof); // EOF reached
            } else {
                return Err(Error::Io(e));
            }
        }

        let pkt_length = str::from_utf8(&length_buf)
            .ok()
            .and_then(|x| usize::from_str_radix(x, 16).ok())
            .map_or_else(
                || {
                    Err(Error::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Invalid pkt-line length",
                    )))
                },
                Ok,
            )?;

        if pkt_length == 0 {
            log::debug!("Received pkt-line: 0000 (flush)");
            return Ok(PktLineReadResult::Flush); // Flush packet
        }

        if pkt_length < 4 {
            return Err(Error::InvalidPacketLength);
        }
        let mut data_buf = vec![0u8; pkt_length - 4];
        self.reader.read_exact(&mut data_buf)?;
        log::debug!(
            "Received pkt-line: {}",
            data_buf[..50.min(data_buf.len())].escape_ascii()
        );
        Ok(PktLineReadResult::Packet(data_buf))
    }

    fn read_pkt_content(&mut self) -> Result<Vec<u8>, Error> {
        let mut content = Vec::new();
        while let Some(mut packet) = self.read_pkt_line()?.without_eof()? {
            content.append(&mut packet);
        }
        Ok(content)
    }

    fn read_pkt_line_text(&mut self) -> Result<PktLineTextResult, Error> {
        PktLineTextResult::try_from(self.read_pkt_line()?)
    }
}

struct PktLineProcess {
    pkt_io: PktLineIO,
    repo: GitRepository,
    config: GitConfig,
    keypair: KeyPair,
}

impl PktLineProcess {
    fn new() -> Result<Self, Error> {
        let repo = GitRepository::new()?;
        let config = load_git_config(&repo)?;
        let keypair = KeyPair::try_from(&config)?;

        Ok(PktLineProcess {
            pkt_io: PktLineIO::new(),
            repo,
            config,
            keypair,
        })
    }

    fn handshake_version(&mut self) -> Result<(), Error> {
        let header = self.pkt_io.read_pkt_line_text()?.into_packet()?;
        if !header.eq("git-filter-client") {
            return Err(Error::InvalidHandshakePayload(header));
        }
        self.pkt_io.write_pkt_string("git-filter-server")?;

        let mut valid_version = false;

        while let Some(payload) = self.pkt_io.read_pkt_line_text()?.without_eof()? {
            match payload.as_str() {
                "version=2" => valid_version = true,
                _ => {
                    log::warn!("Unknown handshake packet: {}", payload);
                }
            }
        }
        if valid_version {
            self.pkt_io.write_pkt_string("version=2")?;
            self.pkt_io.write_flush_pkt()?;
            Ok(())
        } else {
            Err(Error::InvalidVersion)
        }
    }

    fn handshake_capabilities(&mut self) -> Result<(), Error> {
        let mut capabilities = Vec::new();
        const CAPABILITY_PREFIX: &str = "capability=";
        const USABLE_CAPABILITIES: &[&str] = &["clean", "smudge"];
        while let Some(payload) =
            PktLineTextResult::try_from(self.pkt_io.read_pkt_line()?)?.without_eof()?
        {
            if payload.starts_with(CAPABILITY_PREFIX) {
                capabilities.push(payload.split_at(CAPABILITY_PREFIX.len()).1.to_string())
            } else {
                log::warn!("Unknown packet: {}", payload);
            }
        }
        for cap in USABLE_CAPABILITIES {
            if capabilities.iter().any(|c| *c == *cap) {
                let response = [CAPABILITY_PREFIX, cap].concat();
                self.pkt_io.write_pkt_string(&response)?;
            }
        }
        self.pkt_io.write_flush_pkt()?;
        Ok(())
    }

    fn handshake(&mut self) -> Result<(), Error> {
        self.handshake_version()?;
        self.handshake_capabilities()?;
        Ok(())
    }

    fn write_error_response(&mut self, e: Error) -> Result<(), Error> {
        log::error!("Error occurred: {:?}", e);
        if let Err(e) = self.pkt_io.write_pkt_string("status=error") {
            log::error!("Failed to write error response: {:?}", e);
            return Err(e);
        }
        if let Err(e) = self.pkt_io.write_flush_pkt() {
            log::error!("Failed to write flush pkt: {:?}", e);
            return Err(e);
        }
        Ok(())
    }

    fn command_clean(&mut self) -> Result<(), Error> {
        let mut pathname = None;
        const PATHNAME_PREFIX: &[u8] = b"pathname=";
        while let Some(payload) = self.pkt_io.read_pkt_line()?.without_eof()? {
            if payload.starts_with(PATHNAME_PREFIX) {
                let mut data = payload.split_at(PATHNAME_PREFIX.len()).1.to_vec();
                if data.ends_with(b"\n") {
                    data.pop();
                }
                pathname = Some(data);
            } else {
                log::warn!("Unknown command arguments: {}", payload.escape_ascii());
            }
        }

        let Some(pathname) = pathname else {
            return self.write_error_response(Error::PathnameIsMissing);
        };

        let data = self.pkt_io.read_pkt_content()?;

        let encrypted = match encrypt(
            &self.keypair,
            &mut self.config,
            &data,
            pathname.as_slice(),
            &mut self.repo,
        ) {
            Ok(enc) => enc,
            Err(e) => {
                return self.write_error_response(e);
            }
        };
        self.pkt_io.write_pkt_content(&encrypted)?;
        self.pkt_io.write_flush_pkt()?;
        Ok(())
    }

    fn command_smudge(&mut self) -> Result<(), Error> {
        let mut pathname = None;
        const PATHNAME_PREFIX: &[u8] = b"pathname=";
        while let Some(payload) = self.pkt_io.read_pkt_line()?.without_eof()? {
            if payload.starts_with(PATHNAME_PREFIX) {
                let mut data = payload.split_at(PATHNAME_PREFIX.len()).1.to_vec();
                if data.ends_with(b"\n") {
                    data.pop();
                }
                pathname = Some(data);
            } else {
                log::warn!("Unknown command arguments: {}", payload.escape_ascii());
            }
        }

        let Some(pathname) = pathname else {
            return self.write_error_response(Error::PathnameIsMissing);
        };

        let data = self.pkt_io.read_pkt_content()?;

        let decrypted = match decrypt(
            &self.keypair,
            &data,
            &mut self.repo,
            &pathname,
            &mut self.config,
        ) {
            Ok(dec) => dec,
            Err(e) => {
                return self.write_error_response(e);
            }
        };
        self.pkt_io.write_pkt_content(&decrypted)?;
        self.pkt_io.write_flush_pkt()?;
        Ok(())
    }

    fn command(&mut self) -> Result<(), Error> {
        // EOFで終了するまでコマンドを処理
        while let Ok(payload) =
            PktLineTextResult::try_from(self.pkt_io.read_pkt_line()?)?.without_eof()
        {
            let Some(payload) = payload else {
                continue;
            };
            match payload.as_str() {
                "command=clean" => {
                    log::debug!("Processing clean command");
                    self.command_clean()?;
                }
                "command=smudge" => {
                    log::debug!("Processing smudge command");
                    self.command_smudge()?;
                }
                _ => {
                    log::warn!("Unknown command: {}", payload);
                    self.pkt_io.write_pkt_string("status=error")?;
                    self.pkt_io.write_flush_pkt()?;
                }
            }
        }
        Ok(())
    }

    fn process(&mut self) -> Result<(), Error> {
        self.handshake()?;
        self.command()?;
        Ok(())
    }
}
