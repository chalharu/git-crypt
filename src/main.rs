use std::{
    cmp,
    collections::{HashMap, HashSet},
    env::current_dir,
    ffi::{OsStr, OsString},
    fs,
    io::{
        self, BufRead, BufReader, BufWriter, ErrorKind, Read, Seek, StdinLock, StdoutLock, Write,
    },
    path::{Path, PathBuf},
    rc::Rc,
    vec,
};

use clap::{Parser, Subcommand};
use git2::{
    Delta, DiffOptions, MergeFileInput, MergeFileOptions, ObjectType, Odb, Oid, Repository,
    TreeWalkMode, TreeWalkResult,
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

#[cfg(target_os = "windows")]
fn should_convert_wsl_path() -> bool {
    let mut sys = sysinfo::System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, false);
    if let Ok(pid) = sysinfo::get_current_pid()
        && let Some(mut process) = sys.process(pid)
    {
        while let Some(ppid) = process.parent()
            && let Some(parent_process) = sys.process(ppid)
        {
            if parent_process.name().eq_ignore_ascii_case("wsl.exe") {
                log::debug!("Detected WSL parent process");
                return true;
            }
            process = parent_process;
        }
    }
    false
}

#[cfg(target_os = "windows")]
fn convert_wsl_path_to_windows(path: &Path) -> Option<PathBuf> {
    if let Ok(output) = std::process::Command::new("wsl")
        .arg("wslpath")
        .arg("-w")
        .arg(path.as_os_str())
        .output()
        && output.status.success()
        && let Ok(converted_path) = String::from_utf8(output.stdout)
    {
        let converted_path = converted_path.trim();
        log::debug!("Converted WSL path: {}", converted_path);
        return Some(PathBuf::from(converted_path));
    }
    None
}

fn normalize_path<P: AsRef<Path>>(path: P) -> Result<PathBuf, Error> {
    // Windows環境では、WSL上のGitから呼び出された場合に、パスがUnix形式になるため、
    // Windowsのパスに変換する必要がある。
    #[cfg(target_os = "windows")]
    if should_convert_wsl_path() {
        if let Some(converted_path) = convert_wsl_path_to_windows(path.as_ref()) {
            Ok(converted_path)
        } else {
            Err(Error::PathnameIsMissing)
        }
    } else {
        Ok(path.as_ref().to_path_buf())
    }
    #[cfg(not(target_os = "windows"))]
    Ok(path.as_ref().to_path_buf())
}

fn main() {
    let cli = Cli::parse();

    if cli.debug {
        if let Err(e) = stderrlog::new()
            .show_module_names(true)
            .verbosity(3)
            .timestamp(stderrlog::Timestamp::Second)
            .init()
        {
            eprintln!("Failed to initialize logging: {}", e);
            std::process::exit(1);
        }
        log::debug!("Debug mode is enabled");
    } else if let Err(e) = stderrlog::new()
        .module(module_path!())
        .verbosity(0)
        .timestamp(stderrlog::Timestamp::Off)
        .show_level(false)
        .init()
    {
        eprintln!("Failed to initialize logging: {}", e);
        std::process::exit(1);
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
            log::debug!("Textconv for file: {:?}", file_path);
            let Ok(file_path) = normalize_path(&file_path) else {
                log::debug!("WSL path conversion failed");
                std::process::exit(1);
            };

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
        } => {
            // WSLパスの変換
            let Ok(base) = normalize_path(&base) else {
                log::debug!("WSL path conversion failed");
                std::process::exit(1);
            };
            let Ok(local) = normalize_path(&local) else {
                log::debug!("WSL path conversion failed");
                std::process::exit(1);
            };
            let Ok(remote) = normalize_path(&remote) else {
                log::debug!("WSL path conversion failed");
                std::process::exit(1);
            };
            match merge(&base, &local, &remote, marker_size.parse().ok(), &file_path) {
                Ok(is_automergeable) => std::process::exit(if is_automergeable { 0 } else { 1 }),
                Err(e) => {
                    log::error!("Error during merge: {}", e);
                    std::process::exit(2);
                }
            }
        }
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
    #[error("Missing decryption key")]
    MissingKey,
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
        for subkey in public_key.public_subkeys.iter() {
            log::debug!("  Subkey: {}", subkey.key_id(),);
        }
        let private_key = read_secret_key(&fs::read(&config.private_key)?)?;
        log::debug!("Loaded private key: {}", private_key.fingerprint());
        for subkey in private_key.secret_subkeys.iter() {
            log::debug!("  Subkey: {}", subkey.key_id(),);
        }
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
}

impl GitConfig {
    // gitの設定を読み込む関数
    fn load(repo: &GitRepository) -> Result<GitConfig, Error> {
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
        })
    }
}

struct EncryptionPolicy {
    config: Rc<GitConfig>,
    regex_cache: Option<Regex>,
    key_id_cache: Option<Vec<u8>>,
}

impl EncryptionPolicy {
    fn new(config: Rc<GitConfig>) -> Self {
        EncryptionPolicy {
            config,
            regex_cache: None,
            key_id_cache: None,
        }
    }

    fn should_encrypt_file_path(&mut self, path: &[u8]) -> Result<bool, Error> {
        if self.regex_cache.is_none() {
            if let Some(ref regex_str) = self.config.encryption_path_regex {
                let compiled_regex = Regex::new(regex_str)?;
                self.regex_cache = Some(compiled_regex);
            } else {
                // 正規表現が設定されていない場合は常にtrueを返す = すべてのファイルを暗号化対象とする
                return Ok(true);
            }
        }
        // ここまで来たら正規表現が存在するのでunwrapして使用
        let regex = self.regex_cache.as_ref().unwrap();
        Ok(regex.is_match(path))
    }

    fn configured_key_id_bytes(&mut self) -> Result<Option<&[u8]>, Error> {
        if self.key_id_cache.is_none() {
            if let Some(ref encryption_key_id) = self.config.encryption_key_id {
                self.key_id_cache = Some(hex::decode(encryption_key_id)?);
            } else {
                // encryption_key_idが設定されていない場合はNoneを返す
                return Ok(None);
            }
        }
        Ok(self.key_id_cache.as_deref())
    }

    fn is_encrypted_for_configured_key(&mut self, message: &Message) -> Result<bool, Error> {
        if let Some(key_id) = self.configured_key_id_bytes()? {
            // log::debug!("Checking message: {:?}", message);
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
                log::debug!(
                    "Message is not encrypted for the configured key ID: {:x?}",
                    key_id
                );
            }
        } else {
            // キーIDが指定されていない場合、すでに暗号化されているならそのまま出力
            return Ok(message.is_encrypted());
        }
        Ok(false)
    }
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

    let config = GitConfig::load(&repo)?;
    let keypair = KeyPair::try_from(&config)?;

    let blob_oid = write_blob(&repo.repo, &mut std::io::stdin().lock())?;

    let mut encryption_policy = EncryptionPolicy::new(Rc::new(config));
    let encrypted = encrypt(&keypair, blob_oid, path, &mut repo, &mut encryption_policy)?;
    
    let odb = repo.repo.odb()?;
    let mut reader = oid_reader(&odb, encrypted)?;
    std::io::copy(&mut reader, &mut std::io::stdout())?;

    Ok(())
}

fn smudge(path: &OsStr) -> Result<(), Error> {
    let mut repo = GitRepository::new()?;

    let config = GitConfig::load(&repo)?;
    let keypair = KeyPair::try_from(&config)?;

    let mut encryption_policy = EncryptionPolicy::new(Rc::new(config));

    let blob_oid = write_blob(&repo.repo, &mut std::io::stdin().lock())?;

    let decrypted = decrypt(
        &keypair,
        blob_oid,
        &mut repo,
        path.as_encoded_bytes(),
        &mut encryption_policy,
    )?;

    let odb = repo.repo.odb()?;
    let mut reader = oid_reader(&odb, decrypted)?;
    std::io::copy(&mut reader, &mut std::io::stdout())?;

    Ok(())
}

fn oid_reader(odb: &Odb, oid: Oid) -> Result<impl Read, git2::Error> {
    odb.reader(oid).map(|(r, _, _)| r)
}

struct DebugReader<R: Read>(R);

impl<R: Read> Read for DebugReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl<R: Read> std::fmt::Debug for DebugReader<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DebugReader<{}>", std::any::type_name::<R>())
    }
}

fn parse_pgp_message<'a, R: BufRead + std::fmt::Debug + Send + 'a>(
    input: R,
) -> Result<Message<'a>, Error> {
    // form_readerは、ArmoredとBinaryの両方に対応している
    let (message, _) = Message::from_reader(input)?;
    Ok(message)
}

#[derive(Clone, Copy)]
enum CacheType {
    Encrypt,
    Decrypt,
}

impl CacheType {
    fn as_str(&self) -> &'static str {
        match self {
            CacheType::Encrypt => "encrypt",
            CacheType::Decrypt => "decrypt",
        }
    }
}

fn cache_ref_name(oid: Oid, cache_type: CacheType) -> String {
    format!("refs/crypt-cache/{}/{}", cache_type.as_str(), oid)
}

fn cache_oid_lookup(
    repo: &GitRepository,
    cache_type: CacheType,
    oid: Oid,
) -> Result<Option<Oid>, Error> {
    let cache_ref = cache_ref_name(oid, cache_type);
    let cache_obj = match repo.repo.find_reference(&cache_ref) {
        Ok(r) => r,
        Err(e) if e.code() == git2::ErrorCode::NotFound => {
            log::debug!("Cache miss for {}: {}", cache_type.as_str(), cache_ref);
            return Ok(None);
        }
        Err(e) => return Err(e.into()),
    };
    let Some(ref_target) = cache_obj.target() else {
        log::debug!("Cache reference found but has no target: {}", cache_ref);
        return Ok(None);
    };
    // ターゲットのOIDが存在するか確認
    match repo.repo.find_blob(ref_target) {
        Ok(_) => {}
        Err(e) if e.code() == git2::ErrorCode::NotFound => {
            log::debug!("Cache reference found but blob not found: {}", cache_ref);
            return Ok(None);
        }
        Err(e) => return Err(e.into()),
    };
    log::debug!("Cache hit for {}: {}", cache_type.as_str(), cache_ref);
    Ok(Some(ref_target))
}

fn cache_update(repo: &GitRepository, raw_oid: Oid, encrypted_oid: Oid) {
    // キャッシュ化
    log::debug!("Caching object");
    // hash-objectの書き込みに成功した場合のみrefを更新
    // 失敗した場合でも出力自体は成功しているため、処理は継続
    let encrypt_ref = cache_ref_name(raw_oid, CacheType::Encrypt);
    let raw_ref = cache_ref_name(encrypted_oid, CacheType::Decrypt);
    if let Err(e) = repo
        .repo
        .reference(&encrypt_ref, encrypted_oid, true, "Update encrypt cache")
    {
        log::warn!("Failed to update encrypt cache reference: {}", e);
    }
    if let Err(e) = repo
        .repo
        .reference(&raw_ref, raw_oid, true, "Update decrypt cache")
    {
        log::warn!("Failed to update decrypt cache reference: {}", e);
    }
}

trait IteratorExt: Iterator + Sized {
    fn try_eq_fn<I: Iterator, E, F: Fn(Option<Self::Item>, Option<I::Item>) -> Result<bool, E>>(
        mut self,
        mut other: I,
        f: F,
    ) -> Result<bool, E> {
        loop {
            let x = self.next();
            let y = other.next();
            if x.is_none() && y.is_none() {
                return Ok(true);
            }
            if !f(x, y)? {
                return Ok(false);
            }
        }
    }
}
impl<I: Iterator> IteratorExt for I {}

fn encrypt<'a, T: 'a + ToPath<'a>>(
    key_pair: &KeyPair,
    oid: Oid,
    path: T,
    repo: &mut GitRepository,
    encryption_policy: &mut EncryptionPolicy,
) -> Result<Oid, Error> {
    if !encryption_policy.should_encrypt_file_path(path.as_bytes())? {
        // 暗号化対象外のファイルの場合はそのまま出力
        log::debug!("File is not subject to encryption, outputting raw data");
        return Ok(oid);
    }

    if let Some(cached) = cache_oid_lookup(repo, CacheType::Encrypt, oid)? {
        // encrypt_refが存在する = このマシンで暗号化したことがある
        return Ok(cached);
    }

    let odb = repo.repo.odb()?;
    let reader = oid_reader(&odb, oid)?;

    if let Ok(message) = parse_pgp_message(BufReader::new(DebugReader(reader)))
        && encryption_policy.is_encrypted_for_configured_key(&message)?
    {
        log::debug!("Data is already encrypted for the configured key, outputting raw data");
        // すでに指定されたキーIDに一致する公開鍵で暗号化されている場合、そのまま出力
        return Ok(oid);
    }

    // インデックスの内容を取得して復号化を試みる
    if let Some(path) = path.to_path()
        && let Some(index_entry) = repo.repo.index()?.get_path(Path::new(path), 0)
    {
        log::debug!("Found index entry for path: {:?}", path);

        if let Ok(blob) = oid_reader(&odb, index_entry.id)
            && let Ok(message) = parse_pgp_message(BufReader::new(DebugReader(blob)))
        {
            log::debug!("Index entry is a valid PGP message, attempting decryption");

            match decrypt_message(message, key_pair) {
                Ok(decrypted_bytes_reader) => {
                    log::debug!("Decrypted data successfully");
                    // インデックスの内容を復号化できた場合、復号化した内容と同一ならば再暗号化せずにそのまま出力
                    let reader = oid_reader(&odb, oid)?;
                    if decrypted_bytes_reader
                        .bytes()
                        .try_eq_fn(reader.bytes(), |x, y| {
                            if let Some(x) = x
                                && let Some(y) = y
                            {
                                // ここでのエラーはIOエラーなので無視せず伝播させる
                                x.and_then(|a| y.map(|b| a == b))
                            } else {
                                Ok(false)
                            }
                        })?
                    {
                        log::debug!(
                            "Decrypted data matches the input data, using cached encrypted object"
                        );
                        cache_update(repo, oid, index_entry.id);
                        return Ok(index_entry.id);
                    }
                }
                Err(e) => {
                    log::debug!("Failed to decrypt index entry: {:?}", e);
                }
            }
        }
    }

    // ファイルを暗号化して出力
    let encryption_subkey = if let Some(key_id) = encryption_policy.configured_key_id_bytes()? {
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

    let reader = oid_reader(&odb, oid)?;
    let mut builder = MessageBuilder::from_reader("", reader)
        .seipd_v1(rand::thread_rng(), SymmetricKeyAlgorithm::AES256);
    builder.compression(CompressionAlgorithm::ZLIB);
    builder.encrypt_to_key(rand::thread_rng(), &encryption_subkey)?;

    let encrypted = builder.to_armored_string(rand::thread_rng(), ArmorOptions::default())?;

    // キャッシュ化
    let encrypt_obj_oid = repo.repo.blob(encrypted.as_bytes())?;
    cache_update(repo, oid, encrypt_obj_oid);

    Ok(encrypt_obj_oid)
}

fn decrypt_message(message: Message, key_pair: &KeyPair) -> Result<impl Read, Error> {
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
            return Err(Error::MissingKey);
        }
        Err(e) => return Err(e.into()),
    };
    let decompressed_data = if decrypted_message.is_compressed() {
        log::debug!("Decompressed data");
        decrypted_message.decompress()?
    } else {
        log::debug!("Data is not compressed");
        decrypted_message
    };
    Ok(decompressed_data)
}

fn decrypt(
    key_pair: &KeyPair,
    data: Oid,
    repo: &mut GitRepository,
    path: &[u8],
    encryption_policy: &mut EncryptionPolicy,
) -> Result<Oid, Error> {
    // キャッシュ確認
    if let Some(cached) = cache_oid_lookup(repo, CacheType::Decrypt, data)? {
        // キャッシュヒット
        return Ok(cached);
    }

    let odb = repo.repo.odb()?;
    let reader = oid_reader(&odb, data)?;

    let message = match parse_pgp_message(BufReader::new(DebugReader(reader))) {
        Ok(msg) => msg,
        Err(e) => {
            // パケットが不正 = 暗号化されていない場合はそのまま出力
            // 本来は平文と破損を区別したいが、現状では区別できないためそのまま出力
            if encryption_policy
                .should_encrypt_file_path(path)
                .unwrap_or(false)
            {
                log::error!("Not a valid PGP message ({:?}), outputting raw data", e);
            } else {
                log::debug!("Not a valid PGP message ({:?}), outputting raw data", e);
            }
            return Ok(data);
        }
    };
    if !message.is_encrypted() {
        // 暗号化されていない場合はそのまま出力
        log::debug!("Message is not encrypted, outputting raw data");
        return Ok(data);
    }
    if !encryption_policy.is_encrypted_for_configured_key(&message)? {
        // 指定されたキーIDに一致する公開鍵で暗号化されていない場合はそのまま出力
        log::debug!("Message is not encrypted for the configured key, outputting raw data");
        return Ok(data);
    }

    let decrypted_bytes_reader = match decrypt_message(message, key_pair) {
        Ok(decrypted_bytes_reader) => decrypted_bytes_reader,
        Err(Error::MissingKey) => {
            // 復号化キーが見つからない場合はそのまま出力
            log::debug!("Missing decryption key, outputting raw data");
            return Ok(data);
        }
        Err(e) => return Err(e),
    };

    // キャッシュ化
    let decrypt_obj_oid = write_blob(&repo.repo, decrypted_bytes_reader)?;

    log::debug!("Caching decrypted object");
    cache_update(repo, decrypt_obj_oid, data);

    Ok(decrypt_obj_oid)
}

fn write_blob<R: Read>(repo: &Repository, reader: R) -> Result<Oid, Error> {
    let writer = repo.blob_writer(None)?;
    let mut buf_writer = BufWriter::new(writer);
    let mut buf_reader = BufReader::new(reader);
    io::copy(&mut buf_reader, &mut buf_writer)?;
    let oid = match buf_writer.into_inner() {
        Ok(w) => w.commit()?,
        Err(e) => return Err(Error::Io(e.into_error())),
    };
    Ok(oid)
}

fn textconv(path: &Path) -> Result<(), Error> {
    let mut repo = GitRepository::new()?;

    let config = GitConfig::load(&repo)?;
    let keypair = KeyPair::try_from(&config)?;

    let mut encryption_policy = EncryptionPolicy::new(Rc::new(config));

    let mut file = fs::OpenOptions::new().read(true).open(path)?;
    let blob_oid = write_blob(&repo.repo, &mut file)?;

    let decrypted = decrypt(
        &keypair,
        blob_oid,
        &mut repo,
        &[], // textconvではパス情報を利用しない
        &mut encryption_policy,
    )?;

    let odb = repo.repo.odb()?;
    let mut reader = oid_reader(&odb, decrypted)?;
    std::io::copy(&mut reader, &mut std::io::stdout())?;

    Ok(())
}

fn pre_commit() -> Result<(), Error> {
    let repo = GitRepository::new()?;
    let config = GitConfig::load(&repo)?;
    let mut encryption_policy = EncryptionPolicy::new(Rc::new(config));

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
            && encryption_policy
                .should_encrypt_file_path(file_path.as_os_str().as_encoded_bytes())?
        {
            let blob = repo.repo.find_blob(oid)?;
            let data = blob.content();

            if let Ok(message) = parse_pgp_message(BufReader::new(data))
                && encryption_policy.is_encrypted_for_configured_key(&message)?
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

/// ファイルポインタを先頭に戻して内容をコピーする
/// writerはflushまで行う
/// set_lenは行わないので、必要に応じて呼び出し元で行うこと
fn copy_with_seek<R: Read + Seek, W: Write + Seek>(
    reader: &mut R,
    writer: &mut W,
) -> Result<(), Error> {
    reader.seek(io::SeekFrom::Start(0))?;
    writer.seek(io::SeekFrom::Start(0))?;
    io::copy(reader, writer)?;
    writer.flush()?;
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
    let config = GitConfig::load(&repo)?;
    let keypair = KeyPair::try_from(&config)?;
    let mut encryption_policy = EncryptionPolicy::new(Rc::new(config));

    let mut base_file = fs::OpenOptions::new().read(true).open(base)?;
    let base_crypted_oid = write_blob(&repo.repo, &mut base_file)?;

    let mut local_file = fs::OpenOptions::new().write(true).read(true).open(local)?;
    let local_crypted_oid = write_blob(&repo.repo, &mut local_file)?;

    let mut remote_file = fs::OpenOptions::new().read(true).open(remote)?;
    let remote_crypted_oid = write_blob(&repo.repo, &mut remote_file)?;

    if local_crypted_oid == remote_crypted_oid {
        // ローカルとリモートが同一ならマージ不要
        log::debug!("Local and remote are identical, no merge needed");
        return Ok(true);
    }

    if base_crypted_oid == remote_crypted_oid {
        // ベースとリモートが同一ならローカルをそのまま採用
        log::debug!("Base and remote are identical, adopting local");
        return Ok(true);
    }

    if base_crypted_oid == local_crypted_oid {
        // ベースとローカルが同一ならリモートをそのまま採用
        log::debug!("Base and local are identical, adopting remote");
        local_file.set_len(0)?; // ファイルを空にする
        copy_with_seek(&mut remote_file, &mut local_file)?;
        return Ok(true);
    }

    let base_data = decrypt(
        &keypair,
        base_crypted_oid,
        &mut repo,
        base.as_os_str().as_encoded_bytes(),
        &mut encryption_policy,
    )?;

    let local_data = decrypt(
        &keypair,
        local_crypted_oid,
        &mut repo,
        local.as_os_str().as_encoded_bytes(),
        &mut encryption_policy,
    )?;

    let remote_data = decrypt(
        &keypair,
        remote_crypted_oid,
        &mut repo,
        remote.as_os_str().as_encoded_bytes(),
        &mut encryption_policy,
    )?;

    if local_data == remote_data {
        // ローカルとリモートが同一ならマージ不要
        log::debug!("Local and remote are identical, no merge needed");
        return Ok(true);
    }

    if base_data == remote_data {
        // ベースとリモートが同一ならローカルをそのまま採用
        log::debug!("Base and remote are identical, adopting local");
        return Ok(true);
    }

    if base_data == local_data {
        // ベースとローカルが同一ならリモートをそのまま採用
        log::debug!("Base and local are identical, adopting remote");
        local_file.set_len(0)?; // ファイルを空にする
        copy_with_seek(&mut remote_file, &mut local_file)?;
        return Ok(true);
    }

    let mut base_obj = MergeFileInput::new();
    let base_data_blob = repo.repo.find_blob(base_data)?;
    base_obj.content(base_data_blob.content());
    base_obj.path(base);

    let mut local_obj = MergeFileInput::new();
    let local_data_blob = repo.repo.find_blob(local_data)?;
    local_obj.content(local_data_blob.content());
    local_obj.path(local);

    let mut remote_obj = MergeFileInput::new();
    let remote_data_blob = repo.repo.find_blob(remote_data)?;
    remote_obj.content(remote_data_blob.content());
    remote_obj.path(remote);

    // ここで3-wayマージを実行する
    let mut file_opts = MergeFileOptions::new();
    if let Some(marker_size) = marker_size {
        file_opts.marker_size(marker_size as u16);
    }

    let result = git2::merge_file(&base_obj, &local_obj, &remote_obj, Some(&mut file_opts))?;
    drop(base_obj);
    drop(local_obj);
    drop(remote_obj);
    drop(base_data_blob);
    drop(local_data_blob);
    drop(remote_data_blob);

    let blob_oid = write_blob(&repo.repo, result.content())?;

    let encrypted = encrypt(
        &keypair,
        blob_oid,
        file_path,
        &mut repo,
        &mut encryption_policy,
    )?;

    local_file.seek(io::SeekFrom::Start(0))?; // ファイルポインタを先頭に戻す
    local_file.set_len(0)?; // ファイルを空にする
    let odb = repo.repo.odb()?;
    let mut reader = oid_reader(&odb, encrypted)?;
    io::copy(&mut reader, &mut local_file)?;
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

    fn write_pkt_content_with_reader<R: Read>(&mut self, mut data: R) -> Result<(), Error> {
        self.write_pkt_string("status=success")?;
        self.write_flush_pkt()?;

        const LARGE_PACKET_MAX: usize = 65520;
        let mut buf = vec![0u8; LARGE_PACKET_MAX - 4];

        loop {
            match data.read(&mut buf) {
                Ok(0) => {
                    // データが空の場合、そのままフラッシュパケットを送信して終了
                    self.write_flush_pkt()?;
                    return Ok(());
                }
                Ok(n) => self.write_pkt_line(&buf[..n])?,
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => {
                    self.write_flush_pkt()?;
                    self.write_pkt_string("status=abort")?;
                    self.write_flush_pkt()?;
                    return Err(Error::Io(e));
                }
            }
        }
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

    fn read_pkt_line_as_reader(&mut self) -> Result<PktContentReader<'_>, Error> {
        Ok(PktContentReader::new(self))
    }

    fn read_pkt_line_text(&mut self) -> Result<PktLineTextResult, Error> {
        PktLineTextResult::try_from(self.read_pkt_line()?)
    }
}

struct PktContentReader<'a> {
    pkt_io: &'a mut PktLineIO,
    finished: bool,
    buffer: Vec<u8>,
}

impl<'a> PktContentReader<'a> {
    fn new(pkt_io: &'a mut PktLineIO) -> Self {
        PktContentReader {
            pkt_io,
            finished: false,
            buffer: Vec::new(),
        }
    }

    fn read_inner(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        if self.finished {
            return Ok(0); // EOF
        }

        while buf.len() > self.buffer.len() {
            if let Some(mut packet) = self.pkt_io.read_pkt_line()?.without_eof()? {
                self.buffer.append(&mut packet);
            } else {
                self.finished = true;
                break;
            }
        }
        let len = cmp::min(buf.len(), self.buffer.len());
        if len == 0 {
            return Ok(0); // EOF
        }

        let mut right = self.buffer.split_off(len);
        core::mem::swap(&mut right, &mut self.buffer);
        buf[..len].copy_from_slice(&right[..len]);

        Ok(len)
    }
}

impl Read for PktContentReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        match self.read_inner(buf) {
            Ok(n) => Ok(n),
            Err(Error::Io(e)) => Err(e),
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
        }
    }
}

struct PktLineProcess {
    pkt_io: PktLineIO,
    repo: GitRepository,
    keypair: KeyPair,
    config: Rc<GitConfig>,
}

impl PktLineProcess {
    fn new() -> Result<Self, Error> {
        let repo = GitRepository::new()?;
        let config = GitConfig::load(&repo)?;
        let keypair = KeyPair::try_from(&config)?;

        Ok(PktLineProcess {
            pkt_io: PktLineIO::new(),
            repo,
            keypair,
            config: Rc::new(config),
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

    fn command_clean(&mut self, encryption_policy: &mut EncryptionPolicy) -> Result<(), Error> {
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

        let data = self.pkt_io.read_pkt_line_as_reader()?;
        let data = write_blob(&self.repo.repo, data)?;

        let encrypted = match encrypt(
            &self.keypair,
            data,
            pathname.as_slice(),
            &mut self.repo,
            encryption_policy,
        ) {
            Ok(enc) => enc,
            Err(e) => {
                return self.write_error_response(e);
            }
        };

        let odb = self.repo.repo.odb()?;
        let mut reader = oid_reader(&odb, encrypted)?;

        self.pkt_io.write_pkt_content_with_reader(&mut reader)?;
        self.pkt_io.write_flush_pkt()?;
        Ok(())
    }

    fn command_smudge(&mut self, encryption_policy: &mut EncryptionPolicy) -> Result<(), Error> {
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

        let data = self.pkt_io.read_pkt_line_as_reader()?;
        let data = write_blob(&self.repo.repo, data)?;

        let decrypted = match decrypt(
            &self.keypair,
            data,
            &mut self.repo,
            &pathname,
            encryption_policy,
        ) {
            Ok(dec) => dec,
            Err(e) => {
                return self.write_error_response(e);
            }
        };

        let odb = self.repo.repo.odb()?;
        let mut reader = oid_reader(&odb, decrypted)?;

        self.pkt_io.write_pkt_content_with_reader(&mut reader)?;
        self.pkt_io.write_flush_pkt()?;
        Ok(())
    }

    fn command(&mut self) -> Result<(), Error> {
        let mut encryption_policy = EncryptionPolicy::new(self.config.clone());
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
                    self.command_clean(&mut encryption_policy)?;
                }
                "command=smudge" => {
                    log::debug!("Processing smudge command");
                    self.command_smudge(&mut encryption_policy)?;
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
