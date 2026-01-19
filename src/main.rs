use std::{
    env::current_dir,
    fs,
    io::{Read, Write as _},
    path::Path,
};

use clap::{Parser, Subcommand};
use pgp::{
    composed::{
        ArmorOptions, Deserializable as _, Message, MessageBuilder, SignedPublicKey,
        SignedSecretKey,
    },
    crypto::sym::SymmetricKeyAlgorithm,
    types::{CompressionAlgorithm, PublicKeyTrait},
};

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
    /// 開発用テストコマンド
    Test,
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
            // TODO: Implement debug trace output
            println!("Smudging...");
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
        Commands::Test => {
            let config =
                load_git_config(&GitRepository::new().unwrap()).expect("Failed to load git config");
            let keypair = KeyPair::try_from(config).expect("Failed to create keypair");

            println!("{:?}", keypair);
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("Failed to load git configuration")]
    GitConfigError(#[from] git2::Error),
    #[error("IO error occurred")]
    IoError(#[from] std::io::Error),
    #[error("PGP error occurred")]
    PgpError(#[from] pgp::errors::Error),
    #[error("Encryption subkey is not valid for encryption")]
    InvalidEncryptionSubkey,
}

#[derive(Debug)]
struct KeyPair {
    public_key: SignedPublicKey,
    private_key: SignedSecretKey,
}

impl TryFrom<GitConfig> for KeyPair {
    type Error = Error;
    fn try_from(config: GitConfig) -> Result<Self, Error> {
        let public_key = read_public_key(&fs::read(config.public_key)?)?;
        let private_key = read_secret_key(&fs::read(config.private_key)?)?;
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
}

// gitの設定を読み込む関数
fn load_git_config(repo: &GitRepository) -> Result<GitConfig, Error> {
    let config = repo.repo.config()?;

    let public_key = config.get_string("git-crypt.public-key")?;
    let private_key = config.get_string("git-crypt.private-key")?;

    Ok(GitConfig {
        public_key,
        private_key,
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

    let keypair = {
        let config = load_git_config(&repo)?;
        KeyPair::try_from(config)?
    };

    let mut data = Vec::new();
    std::io::stdin().lock().read_to_end(&mut data)?;

    let encrypted = encrypt(&keypair, &data, path, &mut repo)?;
    std::io::stdout().write_all(&encrypted)?;

    Ok(())
}

fn encrypt(
    key_pair: &KeyPair,
    data: &[u8],
    path: &Path,
    repo: &mut GitRepository,
) -> Result<Vec<u8>, Error> {
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
        && message.is_encrypted()
    {
        // すでに署名されている場合はそのまま出力
        return Ok(data.to_vec());
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
        {
            if decompressed_bytes.iter().eq(data.iter()) {
                // キャッシュ化
                let raw_ref = format!("refs/crypt-cache/decrypt/{}", index_entry.id);

                // 失敗しても無視
                let _ =
                    repo.repo
                        .reference(&encrypt_ref, index_entry.id, true, "Update encrypt cache");
                let _ = repo
                    .repo
                    .reference(&raw_ref, oid, true, "Update decrypt cache")?;

                return Ok(blob.content().to_vec());
            }
        }
    }

    // ファイルを暗号化して出力
    let encryption_subkey = &key_pair.public_key.public_subkeys[0];
    if !encryption_subkey.is_encryption_key() {
        return Err(Error::InvalidEncryptionSubkey);
    }

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
        repo.repo
            .reference(&encrypt_ref, encrypt_obj_oid, true, "Update encrypt cache")?;
        repo.repo
            .reference(&raw_ref, oid, true, "Update decrypt cache")?;
    }

    Ok(encrypted.as_bytes().to_vec())
}
