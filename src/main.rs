use std::{
    cmp,
    collections::{HashMap, HashSet},
    env::current_dir,
    ffi::{OsStr, OsString},
    fs::{self, File},
    io::{
        self, BufRead, BufReader, BufWriter, ErrorKind, Read, Seek, StdinLock, StdoutLock, Write,
    },
    os::unix::ffi::OsStrExt,
    path::{self, Path, PathBuf},
    rc::Rc,
    str::FromStr,
    vec,
};

use clap::{Args, Parser, Subcommand, ValueEnum};
use colored::{Color, Colorize};
use git2::{
    Config, Delta, DiffOptions, MergeFileInput, MergeFileOptions, ObjectType, Odb, Oid,
    TreeWalkMode, TreeWalkResult,
};
use inquire::{
    Confirm, CustomType, Select, Text, set_global_render_config,
    ui::RenderConfig,
    validator::{CustomTypeValidator, ErrorMessage, Validation},
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
use similar::ChangeTag;

#[derive(Parser, Clone, Debug)]
struct Cli {
    /// デバッグトレース出力を有効化
    #[arg(short, long, conflicts_with_all = ["verbosity", "debug_all"])]
    debug: bool,
    /// すべてのデバッグトレース出力を有効化
    #[arg(long, conflicts_with_all = ["verbosity", "debug"])]
    debug_all: bool,
    /// ログの冗長性レベル (error, warn, debug, debug-all)
    #[arg(short, long, conflicts_with_all = ["debug", "debug_all"])]
    verbosity: Option<Verbosity>,
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
    /// git-cryptの初期化コマンド
    Setup {
        #[command(flatten)]
        args: SetupArguments,
    },
}

#[derive(Clone, Debug, ValueEnum)]
enum Verbosity {
    #[value(aliases = ["0", "e", "err"])]
    Error, // 0
    #[value(aliases = ["1", "w", "warning"])]
    Warn, // 1
    #[value(aliases = ["2", "d"])]
    Debug, // 2
    #[value(aliases = ["3", "debug_all"])]
    DebugAll, // 3
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

fn try_normalize_path<P: AsRef<Path>>(path: P) -> Result<PathBuf, Error> {
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

fn normalize_path<P: AsRef<Path>>(path: P) -> PathBuf {
    let Ok(path) = try_normalize_path(&path) else {
        log::debug!("WSL path conversion failed");
        std::process::exit(1);
    };
    path
}

fn main() {
    let cli = Cli::parse();

    let verbosity = if let Some(v) = cli.verbosity {
        v
    } else if cli.debug {
        Verbosity::Debug
    } else if cli.debug_all {
        Verbosity::DebugAll
    } else {
        Verbosity::Error
    };

    let mut logger = stderrlog::new();

    if let Err(e) = match verbosity {
        Verbosity::Error => logger
            .module(module_path!())
            .verbosity(0)
            .timestamp(stderrlog::Timestamp::Off)
            .show_level(false),
        Verbosity::Warn => logger
            .module(module_path!())
            .verbosity(1)
            .timestamp(stderrlog::Timestamp::Second)
            .show_level(true),
        Verbosity::Debug => logger
            .module(module_path!())
            .verbosity(3)
            .timestamp(stderrlog::Timestamp::Second)
            .show_level(true),
        Verbosity::DebugAll => logger
            .show_module_names(true)
            .verbosity(3)
            .timestamp(stderrlog::Timestamp::Second)
            .show_level(true),
    }
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
            if let Err(e) = textconv(&normalize_path(file_path)) {
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
            match merge(
                &normalize_path(base),
                &normalize_path(local),
                &normalize_path(remote),
                marker_size.parse().ok(),
                &file_path,
            ) {
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
        Commands::Setup { args } => {
            if let Err(e) = setup(&args) {
                log::error!("Setup failed: {}", e);
                std::process::exit(1);
            }
        }
    }
}

#[derive(Args, Clone, Debug)]
// #[group(required = true, multiple = false)]
pub struct SetupArguments {
    /// 公開鍵ファイルパス, 未指定時に既存設定がない場合はエラー
    #[arg(long, aliases = ["pubkey"])]
    public_key: Option<PathBuf>,
    /// 秘密鍵ファイルパス, 未指定時に既存設定がない場合はエラー
    #[arg(long, aliases = ["privkey"])]
    private_key: Option<PathBuf>,
    /// 暗号化サブキーID, 公開鍵・秘密鍵ファイルに含まれない場合はエラー
    /// 公開鍵内の最初の暗号化サブキーを使用する場合は指定不要
    #[arg(long, aliases = ["keyid"])]
    encryption_key_id: Option<String>,
    /// 暗号化対象パス正規表現, 未指定時に既存設定がない場合はすべてのファイルを暗号化対象とする
    #[arg(long, aliases = ["pathregex"])]
    encryption_path_regex: Option<String>,
    /// フィルタ名, 未指定時は"crypt"を使用
    #[arg(long, aliases = ["filter"])]
    filter_name: Option<String>,
    /// 非対話実行
    #[arg(long, short)]
    yes: bool,
    /// 設定を強制上書き
    #[arg(long, short)]
    force: bool,
    /// Dry-run Mode
    #[arg(long, aliases = ["dry"])]
    dry_run: bool,
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
    #[error("Invalid git repository")]
    InvalidGitRepository,
    #[error("Prompt error occurred: {0}")]
    Prompt(#[from] inquire::error::InquireError),
    #[error("Setup error occurred")]
    Setup,
    #[error("Path is outside of the repository")]
    PathIsOutsideOfRepository,
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
    const CONFIG_SECTION: &'static str = "git-crypt";
    const PUBLIC_KEY: &'static str = "public-key";
    const PRIVATE_KEY: &'static str = "private-key";
    const ENCRYPTION_PATH_REGEX: &'static str = "encryption-path-regex";
    const ENCRYPTION_KEY_ID: &'static str = "encryption-key-id";

    fn combine_section_key(key: &str) -> String {
        format!("{}.{}", Self::CONFIG_SECTION, key)
    }

    // gitの設定を読み込む関数
    fn load(repo: &GitRepository) -> Result<GitConfig, Error> {
        let config = repo.repo.config()?;

        let public_key = config.get_string(&Self::combine_section_key(Self::PUBLIC_KEY))?;
        let private_key = config.get_string(&Self::combine_section_key(Self::PRIVATE_KEY))?;
        let encryption_path_regex = config
            .get_string(&Self::combine_section_key(Self::ENCRYPTION_PATH_REGEX))
            .ok();
        let encryption_key_id = config
            .get_string(&Self::combine_section_key(Self::ENCRYPTION_KEY_ID))
            .ok();

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

    fn copy_oid_to_writer<W: Write>(&self, oid: Oid, writer: &mut W) -> Result<(), Error> {
        let odb = self.repo.odb()?;
        let mut reader = oid_reader(&odb, oid)?;
        std::io::copy(&mut reader, writer)?;
        Ok(())
    }

    fn write_blob<R: Read>(&self, reader: R) -> Result<Oid, Error> {
        let writer = self.repo.blob_writer(None)?;
        let mut buf_writer = BufWriter::new(writer);
        let mut buf_reader = BufReader::new(reader);
        io::copy(&mut buf_reader, &mut buf_writer)?;
        let oid = match buf_writer.into_inner() {
            Ok(w) => w.commit()?,
            Err(e) => return Err(Error::Io(e.into_error())),
        };
        Ok(oid)
    }
}

fn clean(path: &OsStr) -> Result<(), Error> {
    let mut context = Context::new()?;
    context.encrypt_io(
        &mut std::io::stdin().lock(),
        path,
        &mut std::io::stdout().lock(),
    )?;
    Ok(())
}

struct Context {
    repo: GitRepository,
    keypair: KeyPair,
    encryption_policy: EncryptionPolicy,
}

impl Context {
    fn new() -> Result<Self, Error> {
        let repo = GitRepository::new()?;
        let config = GitConfig::load(&repo)?;
        let keypair = KeyPair::try_from(&config)?;
        let encryption_policy = EncryptionPolicy::new(Rc::new(config));
        Ok(Context {
            repo,
            keypair,
            encryption_policy,
        })
    }

    fn decrypt_io<R: Read, W: Write>(
        &mut self,
        reader: &mut R,
        path: &[u8],
        writer: &mut W,
    ) -> Result<(), Error> {
        let blob_oid = self.repo.write_blob(reader)?;
        let decrypted = decrypt(self, blob_oid, path)?;
        self.repo.copy_oid_to_writer(decrypted, writer)?;
        Ok(())
    }

    fn encrypt_io<'a, T: 'a + ToPath<'a>, R: Read, W: Write>(
        &mut self,
        reader: &mut R,
        path: T,
        writer: &mut W,
    ) -> Result<(), Error> {
        let blob_oid = self.repo.write_blob(reader)?;
        let encrypted = encrypt(self, blob_oid, path)?;
        self.repo.copy_oid_to_writer(encrypted, writer)?;
        Ok(())
    }
}

fn smudge(path: &OsStr) -> Result<(), Error> {
    let mut context = Context::new()?;
    context.decrypt_io(
        &mut std::io::stdin().lock(),
        path.as_encoded_bytes(),
        &mut std::io::stdout().lock(),
    )?;
    Ok(())
}

fn oid_reader<'a>(odb: &'a Odb<'a>, oid: Oid) -> Result<impl Read + 'a, git2::Error> {
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

fn parse_pgp_from_oid<'a>(odb: &'a Odb<'a>, oid: Oid) -> Result<Message<'a>, Error> {
    let reader = oid_reader(odb, oid)?;
    parse_pgp_message(BufReader::new(DebugReader(reader)))
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

fn encrypt<'a, T: 'a + ToPath<'a>>(context: &mut Context, oid: Oid, path: T) -> Result<Oid, Error> {
    if !context
        .encryption_policy
        .should_encrypt_file_path(path.as_bytes())?
    {
        // 暗号化対象外のファイルの場合はそのまま出力
        log::debug!("File is not subject to encryption, outputting raw data");
        return Ok(oid);
    }

    if let Some(cached) = cache_oid_lookup(&context.repo, CacheType::Encrypt, oid)? {
        // encrypt_refが存在する = このマシンで暗号化したことがある
        return Ok(cached);
    }

    let odb = context.repo.repo.odb()?;

    if let Ok(message) = parse_pgp_from_oid(&odb, oid)
        && context
            .encryption_policy
            .is_encrypted_for_configured_key(&message)?
    {
        log::debug!("Data is already encrypted for the configured key, outputting raw data");
        // すでに指定されたキーIDに一致する公開鍵で暗号化されている場合、そのまま出力
        return Ok(oid);
    }

    // インデックスの内容を取得して復号化を試みる
    if let Some(path) = path.to_path()
        && let Some(index_entry) = context.repo.repo.index()?.get_path(Path::new(path), 0)
    {
        log::debug!("Found index entry for path: {:?}", path);

        if let Ok(message) = parse_pgp_from_oid(&odb, index_entry.id) {
            log::debug!("Index entry is a valid PGP message, attempting decryption");

            match decrypt_message(message, &context.keypair) {
                Ok(decrypted_bytes_reader) => {
                    log::debug!("Decrypted data successfully");
                    // インデックスの内容を復号化できた場合、復号化した内容と同一ならば再暗号化せずにそのまま出力
                    let reader = oid_reader(&odb, oid)?;
                    if BufReader::new(decrypted_bytes_reader).bytes().try_eq_fn(
                        BufReader::new(reader).bytes(),
                        |x, y| {
                            if let Some(x) = x
                                && let Some(y) = y
                            {
                                // ここでのエラーはIOエラーなので無視せず伝播させる
                                x.and_then(|a| y.map(|b| a == b))
                            } else {
                                Ok(false)
                            }
                        },
                    )? {
                        log::debug!(
                            "Decrypted data matches the input data, using cached encrypted object"
                        );
                        cache_update(&context.repo, oid, index_entry.id);
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
    let encryption_subkey =
        if let Some(key_id) = context.encryption_policy.configured_key_id_bytes()? {
            // 指定されたキーIDに一致するサブキーを探す
            context
                .keypair
                .public_key
                .public_subkeys
                .iter()
                .find(|subkey| {
                    subkey.is_encryption_key()
                        && subkey
                            .as_unsigned()
                            .key_id()
                            .as_ref()
                            .iter()
                            .eq(key_id.iter())
                })
        } else {
            context
                .keypair
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

    let mut writer = context.repo.repo.blob_writer(None)?;
    builder.to_armored_writer(rand::thread_rng(), ArmorOptions::default(), &mut writer)?;
    let encrypt_obj_oid = writer.commit()?;

    cache_update(&context.repo, oid, encrypt_obj_oid);

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

fn decrypt(context: &mut Context, data: Oid, path: &[u8]) -> Result<Oid, Error> {
    // キャッシュ確認
    if let Some(cached) = cache_oid_lookup(&context.repo, CacheType::Decrypt, data)? {
        // キャッシュヒット
        return Ok(cached);
    }

    let odb = context.repo.repo.odb()?;
    let message = match parse_pgp_from_oid(&odb, data) {
        Ok(msg) => msg,
        Err(e) => {
            // パケットが不正 = 暗号化されていない場合はそのまま出力
            // 本来は平文と破損を区別したいが、現状では区別できないためそのまま出力
            if context
                .encryption_policy
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
    if !context
        .encryption_policy
        .is_encrypted_for_configured_key(&message)?
    {
        // 指定されたキーIDに一致する公開鍵で暗号化されていない場合はそのまま出力
        log::debug!("Message is not encrypted for the configured key, outputting raw data");
        return Ok(data);
    }

    let decrypted_bytes_reader = match decrypt_message(message, &context.keypair) {
        Ok(decrypted_bytes_reader) => decrypted_bytes_reader,
        Err(Error::MissingKey) => {
            // 復号化キーが見つからない場合はそのまま出力
            log::debug!("Missing decryption key, outputting raw data");
            return Ok(data);
        }
        Err(e) => return Err(e),
    };

    // キャッシュ化
    let decrypt_obj_oid = context.repo.write_blob(decrypted_bytes_reader)?;

    log::debug!("Caching decrypted object");
    cache_update(&context.repo, decrypt_obj_oid, data);

    Ok(decrypt_obj_oid)
}

fn textconv(path: &Path) -> Result<(), Error> {
    let mut context = Context::new()?;

    context.decrypt_io(
        &mut fs::OpenOptions::new().read(true).open(path)?,
        &[],
        &mut std::io::stdout().lock(),
    )?;
    Ok(())
}

fn pre_commit() -> Result<(), Error> {
    let repo = GitRepository::new()?;
    let config = GitConfig::load(&repo)?;
    let mut encryption_policy = EncryptionPolicy::new(Rc::new(config));
    let odb = repo.repo.odb()?;

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
            if let Ok(message) = parse_pgp_from_oid(&odb, oid)
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

fn resolve_trivial_merge<T: Eq>(
    local: T,
    base: T,
    remote: T,
    local_file: &mut File,
    remote_file: &mut File,
) -> Result<bool, Error> {
    if local == remote {
        // ローカルとリモートが同一ならマージ不要
        log::debug!("Local and remote are identical, no merge needed");
        return Ok(true);
    }

    if base == remote {
        // ベースとリモートが同一ならローカルをそのまま採用
        log::debug!("Base and remote are identical, adopting local");
        return Ok(true);
    }

    if base == local {
        // ベースとローカルが同一ならリモートをそのまま採用
        log::debug!("Base and local are identical, adopting remote");
        local_file.set_len(0)?; // ファイルを空にする
        copy_with_seek(remote_file, local_file)?;
        return Ok(true);
    }

    Ok(false)
}

fn merge(
    base: &Path,
    local: &Path,
    remote: &Path,
    marker_size: Option<usize>,
    file_path: &OsStr,
) -> Result<bool, Error> {
    let mut context = Context::new()?;

    let mut base_file = fs::OpenOptions::new().read(true).open(base)?;
    let base_crypted_oid = context.repo.write_blob(&mut base_file)?;

    let mut local_file = fs::OpenOptions::new().write(true).read(true).open(local)?;
    let local_crypted_oid = context.repo.write_blob(&mut local_file)?;

    let mut remote_file = fs::OpenOptions::new().read(true).open(remote)?;
    let remote_crypted_oid = context.repo.write_blob(&mut remote_file)?;

    if resolve_trivial_merge(
        local_crypted_oid,
        base_crypted_oid,
        remote_crypted_oid,
        &mut local_file,
        &mut remote_file,
    )? {
        return Ok(true);
    }

    let base_data = decrypt(
        &mut context,
        base_crypted_oid,
        base.as_os_str().as_encoded_bytes(),
    )?;

    let local_data = decrypt(
        &mut context,
        local_crypted_oid,
        local.as_os_str().as_encoded_bytes(),
    )?;

    let remote_data = decrypt(
        &mut context,
        remote_crypted_oid,
        remote.as_os_str().as_encoded_bytes(),
    )?;

    if resolve_trivial_merge(
        local_data,
        base_data,
        remote_data,
        &mut local_file,
        &mut remote_file,
    )? {
        return Ok(true);
    }

    let mut base_obj = MergeFileInput::new();
    let base_data_blob = context.repo.repo.find_blob(base_data)?;
    base_obj.content(base_data_blob.content());
    base_obj.path(base);

    let mut local_obj = MergeFileInput::new();
    let local_data_blob = context.repo.repo.find_blob(local_data)?;
    local_obj.content(local_data_blob.content());
    local_obj.path(local);

    let mut remote_obj = MergeFileInput::new();
    let remote_data_blob = context.repo.repo.find_blob(remote_data)?;
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

    local_file.seek(io::SeekFrom::Start(0))?; // ファイルポインタを先頭に戻す
    local_file.set_len(0)?; // ファイルを空にする

    context.encrypt_io(&mut result.content(), file_path, &mut local_file)?;
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
            Err(e) => Err(io::Error::other(e)),
        }
    }
}

struct PktLineProcess {
    context: Context,
    pkt_io: PktLineIO,
}

#[derive(Clone, Copy)]
enum ProcessCommand {
    Clean,
    Smudge,
}

impl PktLineProcess {
    fn new() -> Result<Self, Error> {
        Ok(PktLineProcess {
            pkt_io: PktLineIO::new(),
            context: Context::new()?,
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

    fn parse_arguments(&mut self) -> Result<HashMap<Vec<u8>, Vec<u8>>, Error> {
        let mut args = HashMap::new();

        while let Some(payload) = self.pkt_io.read_pkt_line()?.without_eof()? {
            let mut parts = payload.splitn(2, |p| *p == b'=');
            let Some(key) = parts.next() else {
                // 空のペイロード
                log::warn!("Invalid argument format (payload is empty)");
                continue;
            };
            let Some(mut value) = parts.next().map(|v| v.to_vec()) else {
                log::warn!("Invalid argument format: {}", payload.escape_ascii());
                continue;
            };
            if value.last() == Some(&b'\n') {
                value.pop();
            }
            if args.insert(key.to_vec(), value).is_some() {
                log::warn!("Duplicate argument key: {}", key.escape_ascii());
            }
        }

        Ok(args)
    }

    fn output_content_with_oid(&mut self, oid: Oid) -> Result<(), Error> {
        let odb = self.context.repo.repo.odb()?;
        let mut reader = oid_reader(&odb, oid)?;

        self.pkt_io.write_pkt_content_with_reader(&mut reader)?;
        self.pkt_io.write_flush_pkt()?;
        Ok(())
    }

    fn get_pathname(args: &HashMap<Vec<u8>, Vec<u8>>) -> Result<&[u8], Error> {
        const PATHNAME_KEY: &[u8] = b"pathname";
        let Some(pathname) = args.get(PATHNAME_KEY) else {
            return Err(Error::PathnameIsMissing);
        };
        Ok(pathname.as_slice())
    }

    fn read_input(
        &mut self,
        args: &HashMap<Vec<u8>, Vec<u8>>,
        command: ProcessCommand,
    ) -> Result<Oid, Error> {
        const BLOB_KEY: &[u8] = b"blob";

        let mut reader = self.pkt_io.read_pkt_line_as_reader()?;

        let oid = if let ProcessCommand::Smudge = command
            && let Some(blob) = args.get(BLOB_KEY)
            && let Ok(oid) = Oid::from_str(String::from_utf8_lossy(blob).as_ref())
        {
            // blob引数がある場合はそのOIDを利用する
            // readerを消費して、pkt-lineの内容を破棄する
            let mut buf = vec![0u8; 8192];
            while reader.read(&mut buf)? > 0 {}
            oid
        } else {
            self.context.repo.write_blob(reader)?
        };
        Ok(oid)
    }

    fn command_clean_or_smudge(&mut self, command: ProcessCommand) -> Result<(), Error> {
        let args = self.parse_arguments()?;
        let pathname = Self::get_pathname(&args)?;
        let data = self.read_input(&args, command)?;

        let f = match command {
            ProcessCommand::Clean => encrypt,
            ProcessCommand::Smudge => decrypt,
        };

        let result_oid = match f(&mut self.context, data, pathname) {
            Ok(r) => r,
            Err(e) => {
                return self.write_error_response(e);
            }
        };

        self.output_content_with_oid(result_oid)
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
                    self.command_clean_or_smudge(ProcessCommand::Clean)?;
                }
                "command=smudge" => {
                    log::debug!("Processing smudge command");
                    self.command_clean_or_smudge(ProcessCommand::Smudge)?;
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

struct InquirePathBuf<'a>(CustomType<'a, PathBuf>);

impl<'a> InquirePathBuf<'a> {
    fn new(message: &'a str, default: Option<PathBuf>, render_config: RenderConfig<'a>) -> Self {
        InquirePathBuf(CustomType {
            message,
            starting_input: None,
            default,
            placeholder: None,
            help_message: None,
            formatter: &|p| p.to_string_lossy().to_string(),
            default_value_formatter: &|p| p.to_string_lossy().to_string(),
            parser: &|i| PathBuf::from_str(i).map_err(|_| ()),
            validators: CustomType::DEFAULT_VALIDATORS,
            error_message: "Invalid input".into(),
            render_config,
        })
    }

    fn with_validator<V>(mut self, validator: V) -> Self
    where
        V: CustomTypeValidator<PathBuf> + 'static,
    {
        self.0.validators.push(Box::new(validator));
        self
    }

    fn prompt(self) -> Result<PathBuf, Error> {
        self.0.prompt().map_err(|_| Error::Setup)
    }
}

fn validate_public_key<P: AsRef<Path>>(
    p: &P,
) -> Result<Validation, Box<dyn std::error::Error + Send + Sync + 'static>> {
    if p.as_ref().as_os_str().to_str().is_none() {
        return Ok(Validation::Invalid(ErrorMessage::Custom(
            "Public key path contains invalid UTF-8 characters".into(),
        )));
    }
    // 鍵ファイルの存在確認と検証
    if !p.as_ref().exists() || !p.as_ref().is_file() {
        return Ok(Validation::Invalid(ErrorMessage::Custom(
            "Public key file does not exist or is not a file".into(),
        )));
    }
    let mut fs = File::options().read(true).open(p)?;
    if fs.metadata()?.len() > 1024 * 1024 {
        // 1MBを超えるファイルは拒否
        // 普通はそんなに大きな公開鍵ファイルは存在しないはず
        return Ok(Validation::Invalid(ErrorMessage::Custom(
            "Public key file is too large (>1MB)".into(),
        )));
    }
    let mut buf = Vec::new();
    fs.read_to_end(&mut buf)?;
    if let Err(e) = read_public_key(&buf) {
        return Ok(Validation::Invalid(ErrorMessage::Custom(format!(
            "Failed to read public key: {}",
            e
        ))));
    }
    Ok(Validation::Valid)
}

fn validate_private_key<P: AsRef<Path>>(
    p: &P,
) -> Result<Validation, Box<dyn std::error::Error + Send + Sync + 'static>> {
    if p.as_ref().as_os_str().to_str().is_none() {
        return Ok(Validation::Invalid(ErrorMessage::Custom(
            "Private key path contains invalid UTF-8 characters".into(),
        )));
    }
    // 鍵ファイルの存在確認と検証
    if !p.as_ref().exists() || !p.as_ref().is_file() {
        return Ok(Validation::Invalid(ErrorMessage::Custom(
            "Private key file does not exist or is not a file".into(),
        )));
    }
    let mut fs = File::options().read(true).open(p)?;
    if fs.metadata()?.len() > 1024 * 1024 {
        // 1MBを超えるファイルは拒否
        // 普通はそんなに大きな公開鍵ファイルは存在しないはず
        return Ok(Validation::Invalid(ErrorMessage::Custom(
            "Private key file is too large (>1MB)".into(),
        )));
    }
    let mut buf = Vec::new();
    fs.read_to_end(&mut buf)?;
    if let Err(e) = read_secret_key(&buf) {
        return Ok(Validation::Invalid(ErrorMessage::Custom(format!(
            "Failed to read public key: {}",
            e
        ))));
    }
    Ok(Validation::Valid)
}

fn validate_encryption_path_regex(
    r: &str,
) -> Result<Validation, Box<dyn std::error::Error + Send + Sync + 'static>> {
    match Regex::new(r) {
        Ok(_) => Ok(Validation::Valid),
        Err(e) => Ok(Validation::Invalid(ErrorMessage::Custom(format!(
            "Invalid regex pattern: {}",
            e
        )))),
    }
}

fn validate_filter_name(
    n: &str,
) -> Result<Validation, Box<dyn std::error::Error + Send + Sync + 'static>> {
    if n.trim().is_empty() {
        return Ok(Validation::Invalid(ErrorMessage::Custom(
            "Filter name cannot be empty".into(),
        )));
    }
    // 英数字、ハイフン、アンダースコアのみを許可
    // 先頭・末尾にハイフン・アンダースコアは許可しない
    if n.is_ascii()
        && n.bytes().enumerate().all(|(i, b)| {
            b.is_ascii_alphanumeric() || (b == b'-' || b == b'_') && i != 0 && i != n.len() - 1
        })
    {
        return Ok(Validation::Valid);
    }
    Ok(Validation::Invalid(ErrorMessage::Custom(
        "Invalid filter name".into(),
    )))
}

struct ConfigChange {
    key: String,
    old_value: Option<String>,
    new_value: Option<String>,
}

struct SetupPlan {
    gitconfig_changes: Vec<ConfigChange>,
    gitattributes_old: Vec<u8>,
    gitattributes_new: Vec<u8>,
}

impl SetupPlan {
    fn has_changes(&self) -> bool {
        (!self.gitconfig_changes.is_empty()
            && self
                .gitconfig_changes
                .iter()
                .any(|c| c.old_value != c.new_value))
            || self.gitattributes_old != self.gitattributes_new
    }
}

fn resolve_public_key(
    args: &SetupArguments,
    config: &Config,
    render_config: RenderConfig,
) -> Result<(PathBuf, SignedPublicKey), Error> {
    let public_key = args
        .public_key
        .clone()
        .or_else(|| {
            config
                .get_path(&GitConfig::combine_section_key(GitConfig::PUBLIC_KEY))
                .ok()
        })
        .filter(|p| validate_public_key(p).is_ok_and(|v| v == Validation::Valid));
    // public_keyを取得
    let public_key = {
        if !args.yes {
            // 対話モード
            InquirePathBuf::new("Public Key Path:", public_key.clone(), render_config)
                .with_validator(validate_public_key)
                .prompt()?
        } else {
            // 非対話モード
            match public_key {
                Some(path) => path.to_path_buf(),
                None => {
                    log::error!("Public key path is not specified");
                    return Err(Error::Setup);
                }
            }
        }
    };
    let public_key_data = {
        let mut fs = File::options().read(true).open(&public_key)?;
        let mut buf = Vec::new();
        fs.read_to_end(&mut buf)?;
        read_public_key(&buf)?
    };
    Ok((public_key, public_key_data))
}

fn resolve_private_key(
    args: &SetupArguments,
    config: &Config,
    render_config: RenderConfig,
) -> Result<(PathBuf, SignedSecretKey), Error> {
    let private_key = args
        .private_key
        .clone()
        .or_else(|| {
            config
                .get_path(&GitConfig::combine_section_key(GitConfig::PRIVATE_KEY))
                .ok()
        })
        .filter(|p| validate_private_key(p).is_ok_and(|v| v == Validation::Valid));

    let private_key = {
        if !args.yes {
            // 対話モード
            InquirePathBuf::new("Private Key Path:", private_key.clone(), render_config)
                .with_validator(validate_private_key)
                .prompt()?
        } else {
            // 非対話モード
            match private_key {
                Some(path) => path,
                None => {
                    log::error!("Private key path is not specified");
                    return Err(Error::Setup);
                }
            }
        }
    };
    let private_key_data = {
        let mut fs = File::options().read(true).open(&private_key)?;
        let mut buf = Vec::new();
        fs.read_to_end(&mut buf)?;
        read_secret_key(&buf)?
    };
    Ok((private_key, private_key_data))
}

fn resolve_encryption_key_id(
    public_key_data: &SignedPublicKey,
    private_key_data: &SignedSecretKey,
    args: &SetupArguments,
    config: &Config,
) -> Result<Option<String>, Error> {
    // encryption_key_idに指定可能なキーID一覧を取得
    let mut public_key_id_list = HashSet::new();
    if public_key_data.is_encryption_key() {
        public_key_id_list.insert(public_key_data.key_id());
    }
    public_key_id_list.extend(
        public_key_data
            .public_subkeys
            .iter()
            .filter(|subkey| subkey.is_encryption_key())
            .map(|s| s.key_id()),
    );

    let mut private_key_id_list = HashSet::new();
    private_key_id_list.insert(private_key_data.key_id());
    private_key_id_list.extend(private_key_data.secret_subkeys.iter().map(|s| s.key_id()));
    let encryption_id_list = public_key_id_list
        .intersection(&private_key_id_list)
        .map(|s| s.to_string())
        .collect::<HashSet<_>>();

    if encryption_id_list.is_empty() {
        log::error!("No encryption subkey found in the provided keys");
        return Err(Error::Setup);
    }

    log::debug!("Available Encryption ID list: {:?}", encryption_id_list);

    let encryption_key_id = args.encryption_key_id.clone().or_else(|| {
        config
            .get_string(&GitConfig::combine_section_key(
                GitConfig::ENCRYPTION_KEY_ID,
            ))
            .ok()
    });
    let encryption_key_id = encryption_key_id.filter(|s| encryption_id_list.contains(s));

    let encryption_key_id = {
        if !args.yes {
            // 対話モード
            let encryption_id_list_vec = encryption_id_list.into_iter().collect::<Vec<_>>();
            let starting_cursor = encryption_key_id
                .as_ref()
                .and_then(|id| encryption_id_list_vec.iter().position(|x| x == id))
                .unwrap_or(0);
            Select::new("Encryption key ID:", encryption_id_list_vec)
                .with_starting_cursor(starting_cursor)
                .prompt_skippable()?
        } else {
            // 非対話モード
            encryption_key_id
        }
    };
    Ok(encryption_key_id)
}

fn resolve_encryption_path_regex(
    args: &SetupArguments,
    config: &Config,
    render_config: RenderConfig,
) -> Result<Option<String>, Error> {
    let encryption_path_regex = args
        .encryption_path_regex
        .clone()
        .or_else(|| {
            config
                .get_string(&GitConfig::combine_section_key(
                    GitConfig::ENCRYPTION_PATH_REGEX,
                ))
                .ok()
        })
        .filter(|p| validate_encryption_path_regex(p).is_ok_and(|v| v == Validation::Valid));

    let encryption_path_regex = {
        if !args.yes {
            // 対話モード
            Text {
                message: "Encryption path regex:",
                placeholder: None,
                initial_value: None,
                default: encryption_path_regex.as_deref(),
                help_message: Text::DEFAULT_HELP_MESSAGE,
                validators: Text::DEFAULT_VALIDATORS,
                formatter: Text::DEFAULT_FORMATTER,
                page_size: Text::DEFAULT_PAGE_SIZE,
                autocompleter: None,
                render_config,
            }
            .with_validator(validate_encryption_path_regex)
            .prompt_skippable()?
        } else {
            // 非対話モード
            encryption_path_regex
        }
    };
    Ok(encryption_path_regex)
}

fn build_gitconfig_changes(
    args: &SetupArguments,
    config: &Config,
    render_config: RenderConfig,
) -> Result<(Vec<ConfigChange>, Vec<PathBuf>), Error> {
    let mut gitconfig_changes = Vec::new();

    // public_keyを取得
    let (public_key, public_key_data) = resolve_public_key(args, config, render_config)?;

    let key = GitConfig::combine_section_key(GitConfig::PUBLIC_KEY);
    gitconfig_changes.push(ConfigChange {
        old_value: config.get_string(&key).ok(),
        key,
        new_value: Some(public_key.to_string_lossy().to_string()),
    });

    // private_keyを取得
    let (private_key, private_key_data) = resolve_private_key(args, config, render_config)?;

    let key = GitConfig::combine_section_key(GitConfig::PRIVATE_KEY);
    gitconfig_changes.push(ConfigChange {
        old_value: config.get_string(&key).ok(),
        key,
        new_value: Some(private_key.to_string_lossy().to_string()),
    });

    let encryption_key_id =
        resolve_encryption_key_id(&public_key_data, &private_key_data, args, config)?;

    let key = GitConfig::combine_section_key(GitConfig::ENCRYPTION_KEY_ID);
    gitconfig_changes.push(ConfigChange {
        old_value: config.get_string(&key).ok(),
        key,
        new_value: encryption_key_id.clone(),
    });

    let encryption_path_regex = resolve_encryption_path_regex(args, config, render_config)?;
    let key = GitConfig::combine_section_key(GitConfig::ENCRYPTION_PATH_REGEX);
    gitconfig_changes.push(ConfigChange {
        old_value: config.get_string(&key).ok(),
        key,
        new_value: encryption_path_regex.clone(),
    });

    Ok((gitconfig_changes, vec![public_key, private_key]))
}

fn build_gitattributes<P: AsRef<Path>>(
    args: &SetupArguments,
    repo: &GitRepository,
    additinal_paths: &[P],
    git_attributes: &[u8],
) -> Result<Vec<u8>, Error> {
    // .gitattributesの設定内容を準備
    // filter_nameが指定されていない場合は"crypt"を使用
    // - `* filter=<FILTER_NAME> diff=<FILTER_NAME> merge=<FILTER_NAME>`
    // - `<PUBLIC_KEY_PATH> filter= diff= merge=`
    // - `<PRIVATE_KEY_PATH> filter= diff= merge=`
    // - `.gitattributes filter= diff= merge=`
    // - `.gitignore filter= diff= merge=`
    // - `.gitkeep filter= diff= merge=`

    let filter_name = {
        if !args.yes {
            // 対話モード
            Text::new("Filter name:")
                .with_default(args.filter_name.as_deref().unwrap_or("crypt"))
                .with_validator(validate_filter_name)
                .prompt()?
        } else {
            // 非対話モード
            args.filter_name.clone().unwrap_or("crypt".into())
        }
    };

    let mut special_files = vec![
        b".gitattributes".to_vec(),
        b".gitignore".to_vec(),
        b".gitkeep".to_vec(),
    ];

    for path in additinal_paths {
        if let Ok(relative_path) = relative_git_path(repo, path.as_ref()) {
            special_files.push(relative_path.as_os_str().as_bytes().to_vec());
        }
    }

    let mut new_gitattributes = Vec::<Vec<u8>>::new();
    for line_buf in git_attributes.split(|&b| b == b'\n') {
        let line = line_buf.trim_ascii_start();
        if line.is_empty() || line.first() == Some(&b'#') {
            // 空行・コメント行はそのまま追加
            new_gitattributes.push(line_buf.to_vec());
            continue;
        }
        // 一度既存設定を全て削除
        let buf = line
            .split(|&b| b.is_ascii_whitespace())
            .filter(|v| !v.is_empty())
            .collect::<Vec<_>>();
        if buf.first() != Some(&b"*".as_slice())
            && !special_files
                .iter()
                .any(|f| Some(&f.as_slice()) == buf.first())
        {
            // `*` または 特殊ファイル以外のパス指定の場合はそのまま追加
            new_gitattributes.push(line_buf.to_vec());
            continue;
        }
        let len = buf.len();
        let buf = buf
            .into_iter()
            .filter(|attr| {
                !attr.starts_with(b"filter=")
                    && !attr.starts_with(b"diff=")
                    && !attr.starts_with(b"merge=")
            })
            .collect::<Vec<_>>();
        if buf.len() < len {
            // 属性の一部が削除された場合は更新
            if buf.len() <= 1 {
                // 属性が1つ以下になった場合はスキップ
                continue;
            }
            new_gitattributes.push(buf.join(&b' '));
        } else {
            // 変更なし
            new_gitattributes.push(line_buf.to_vec());
        }
    }

    if new_gitattributes.iter().all(|line| line.is_empty()) {
        // 全ての行が空行の場合はクリア
        new_gitattributes.clear();
    }

    // ここまでで既存のfilter設定を削除したので、新しい設定を追加
    new_gitattributes.insert(
        0,
        format!(
            "* filter={} diff={} merge={}",
            filter_name, filter_name, filter_name
        )
        .as_bytes()
        .to_vec(),
    );

    for special_file in special_files.as_slice() {
        let mut buf = special_file.clone();
        buf.extend_from_slice(b" filter= diff= merge=");
        new_gitattributes.push(buf);
    }

    let new_gitattributes = new_gitattributes.join(&b'\n');
    Ok(new_gitattributes)
}

fn build_setup_plan(
    config: &Config,
    git_attributes: &[u8],
    args: &SetupArguments,
    repo: &GitRepository,
) -> Result<SetupPlan, Error> {
    // RenderConfigを設定
    // CustomTypeで利用する設定と一致させるため、ここでグローバルに設定する
    let render_config = RenderConfig::default();
    set_global_render_config(render_config);

    let (gitconfig_changes, keys) = build_gitconfig_changes(args, config, render_config)?;

    let new_gitattributes = build_gitattributes(args, repo, &keys, git_attributes)?;
    Ok(SetupPlan {
        gitconfig_changes,
        gitattributes_old: git_attributes.to_vec(),
        gitattributes_new: new_gitattributes,
    })
}

fn print_setup_plan(setup_plan: &SetupPlan) {
    println!();
    println!("[Git Config Changes]");
    setup_plan.gitconfig_changes.iter().for_each(|change| {
        if change.old_value == change.new_value {
            if let Some(v) = change.new_value.as_ref() {
                println!("  {} = {}", change.key, v);
            }
        } else {
            if let Some(v) = change.old_value.as_ref() {
                println!("{}", format!("- {} = {}", change.key, v).red());
            }
            if let Some(v) = change.new_value.as_ref() {
                println!("{}", format!("+ {} = {}", change.key, v).green());
            }
        }
    });

    println!();
    println!("[.gitattributes Changes]");

    println!("-----");
    for change in similar::TextDiff::from_lines(
        &String::from_utf8_lossy(&setup_plan.gitattributes_old),
        &String::from_utf8_lossy(&setup_plan.gitattributes_new),
    )
    .iter_all_changes()
    {
        let (sign, color) = match change.tag() {
            ChangeTag::Delete => ("-", Color::Red),
            ChangeTag::Insert => ("+", Color::Green),
            ChangeTag::Equal => (" ", Color::White),
        };
        let out = format!("{} {}", sign, change).color(color);
        print!("{}", out);
    }
    println!("-----");
    println!();
}

fn apply_setup_plan(
    setup_plan: &SetupPlan,
    config: &mut Config,
    gitattributes_path: &Path,
) -> Result<(), Error> {
    // 設定を適用
    for change in setup_plan.gitconfig_changes.iter() {
        if change.new_value != change.old_value {
            if let Some(new_value) = change.new_value.as_ref() {
                config.set_str(&change.key, new_value)?;
            } else {
                config.remove(&change.key)?;
            }
        }
    }
    std::fs::File::options()
        .write(true)
        .create(true)
        .truncate(true)
        .open(gitattributes_path)?
        .write_all(&setup_plan.gitattributes_new)?;

    Ok(())
}

/// 初期設定を行う
fn setup(args: &SetupArguments) -> Result<(), Error> {
    // Gitリポジトリであることを確認
    let repo = GitRepository::new()?;

    // bareリポジトリに対しては処理を行わない
    let Some(workdir) = repo.repo.workdir() else {
        log::error!("Repository is bare, cannot setup encryption filter");
        return Err(Error::InvalidGitRepository);
    };

    // Git設定
    let mut config = repo.repo.config()?;

    let gitattributes_path = workdir.join(".gitattributes");

    let gitattributes_file = match std::fs::File::options()
        .read(true)
        .open(&gitattributes_path)
    {
        Ok(f) => Some(f),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(Error::Io(e)),
    };

    let git_attributes = if let Some(mut f) = gitattributes_file {
        let mut content = Vec::new();
        f.read_to_end(&mut content)?;
        content
    } else {
        Vec::new()
    };

    let setup_plan = build_setup_plan(&config, &git_attributes, args, &repo)?;

    // diff表示
    print_setup_plan(&setup_plan);

    if args.dry_run {
        println!("Dry-run mode: No changes were applied.");
        return Ok(());
    }

    // 変更がある場合のみ適用
    if setup_plan.has_changes() {
        // ユーザ確認
        if !args.force && !args.yes {
            // 対話モード
            let proceed = Confirm::new("Apply these changes?")
                .with_default(false)
                .prompt()?;
            if !proceed {
                println!("Aborted by user.");
                return Ok(());
            }
        }
        apply_setup_plan(&setup_plan, &mut config, &gitattributes_path)?;
    }

    Ok(())
}

fn relative_git_path(repo: &GitRepository, path: &Path) -> Result<PathBuf, Error> {
    // ワーキングディレクトリを取得
    let workdir = repo.repo.workdir().ok_or(Error::InvalidGitRepository)?;

    let abs_path = path::absolute(path.canonicalize()?)?;
    let abs_workdir = path::absolute(workdir.canonicalize()?)?;
    abs_path
        .strip_prefix(&abs_workdir)
        .map(|p| p.to_path_buf())
        .map_err(|_| Error::PathIsOutsideOfRepository)
}
