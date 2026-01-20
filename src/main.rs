use std::{
    env::current_dir,
    fs,
    io::{Read, Write as _},
    path::Path,
};

use clap::{Parser, Subcommand};
use pgp::{
    composed::{
        ArmorOptions, DecryptionOptions, Deserializable as _, Esk, Message, MessageBuilder,
        SignedPublicKey, SignedSecretKey, TheRing,
    },
    crypto::sym::SymmetricKeyAlgorithm,
    types::{CompressionAlgorithm, KeyDetails, PublicKeyTrait},
};
use regex::Regex;

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
        file_path: String,
    },
    /// git smudgeフィルタ用コマンド
    Smudge,
    /// git textconvフィルタ用コマンド
    Textconv {
        /// ファイルパス
        #[arg(index = 1)]
        file_path: String,
    },
    /// git mergeドライバ用コマンド
    Merge {
        /// ベースファイルパス
        #[arg(index = 1)]
        base: String,
        /// ローカルファイルパス
        #[arg(index = 2)]
        local: String,
        /// リモートファイルパス
        #[arg(index = 3)]
        remote: String,
        /// マーカーサイズ
        #[arg(index = 4)]
        marker_size: String,
        /// ファイルパス
        #[arg(index = 5)]
        file_path: String,
    },
    /// git pre-commitフック用コマンド
    PreCommit,
    /// git pre-auto-gcフック用コマンド
    PreAutoGc,
    /// git clean/smudgeのprocessコマンド
    Process,
}

fn main() {
    let cli = Cli::parse();

    if cli.debug {
        // TODO: Implement debug trace output
        println!("Debug mode is enabled");
    }

    match cli.command {
        Commands::Clean { file_path } => {
            if let Err(e) = clean(Path::new(&file_path)) {
                eprintln!("Error during clean: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Smudge => {
            if let Err(e) = smudge() {
                eprintln!("Error during smudge: {:?}", e);
                std::process::exit(1);
            }
        }
        Commands::Textconv { file_path } => {
            // TODO: Implement debug trace output
            println!("Text converting file: {}", file_path);
        }
        Commands::Merge {
            base,
            local,
            remote,
            marker_size,
            file_path,
        } => {
            // TODO: Implement debug trace output
            println!(
                "Merging files: {} {} {} {} {}",
                base, local, remote, marker_size, file_path
            );
        }
        Commands::PreCommit => {
            // TODO: Implement debug trace output
            println!("Running pre-commit hooks...");
        }
        Commands::PreAutoGc => {
            // TODO: Implement debug trace output
            println!("Running pre-auto-gc hooks...");
        }
        Commands::Process => {
            // TODO: Implement debug trace output
            println!("Processing...");
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
        let private_key = read_secret_key(&fs::read(&config.private_key)?)?;
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
    fn is_encryption(&mut self, path: &Path) -> Result<bool, Error> {
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
        Ok(regex.is_match(path.to_str().unwrap_or_default()))
    }

    fn is_encrypted_by_key(&mut self, message: &Message) -> Result<bool, Error> {
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

fn clean(path: &Path) -> Result<(), Error> {
    let mut repo = GitRepository::new()?;

    let mut config = load_git_config(&repo)?;
    let keypair = KeyPair::try_from(&config)?;

    let mut data = Vec::new();
    std::io::stdin().lock().read_to_end(&mut data)?;

    let encrypted = encrypt(&keypair, &mut config, &data, path, &mut repo)?;
    std::io::stdout().write_all(&encrypted)?;

    Ok(())
}

fn smudge() -> Result<(), Error> {
    let mut repo = GitRepository::new()?;

    let config = load_git_config(&repo)?;
    let keypair = KeyPair::try_from(&config)?;

    let mut data = Vec::new();
    std::io::stdin().lock().read_to_end(&mut data)?;

    let decrypted = decrypt(&keypair, &data, &mut repo)?;
    std::io::stdout().write_all(&decrypted)?;

    Ok(())
}

fn encrypt(
    key_pair: &KeyPair,
    config: &mut GitConfig,
    data: &[u8],
    path: &Path,
    repo: &mut GitRepository,
) -> Result<Vec<u8>, Error> {
    if !config.is_encryption(path)? {
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

    if let Ok(message) = Message::from_bytes(data)
    {
        if config.is_encrypted_by_key(&message)? {
            // すでに指定されたキーIDに一致する公開鍵で暗号化されている場合、そのまま出力
            return Ok(data.to_vec());
        }
    }

    // インデックスの内容を取得して復号化を試みる
    if let Some(index_entry) = repo.repo.index()?.get_path(path, 0)
        && let Ok(blob) = repo.repo.find_blob(index_entry.id)
        && let Ok(message) = Message::from_bytes(blob.content())
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
    builder
        .encrypt_to_key(rand::thread_rng(), &encryption_subkey)
        .unwrap();

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

fn decrypt(key_pair: &KeyPair, data: &[u8], repo: &mut GitRepository) -> Result<Vec<u8>, Error> {
    let Ok((message, _)) = Message::from_armor(data) else {
        // Messageオブジェクトに変換できない場合 = 暗号化されていない場合、パケットが壊れている場合はそのまま出力
        return Ok(data.to_vec());
    };
    if !message.is_encrypted() {
        // 暗号化されていない場合はそのまま出力
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
