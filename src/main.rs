use std::{env::current_dir, fs};

use clap::{Parser, Subcommand};
use pgp::composed::{Deserializable as _, SignedPublicKey, SignedSecretKey};

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
            // TODO: Implement debug trace output
            println!("Cleaning file: {}", file_path);
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
            let config = load_git_config().expect("Failed to load git config");
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
fn load_git_config() -> Result<GitConfig, Error> {
    let repo = git2::Repository::open(current_dir()?)?;
    let config = repo.config()?;

    let public_key = config.get_string("git-crypt.public-key")?;
    let private_key = config.get_string("git-crypt.private-key")?;

    Ok(GitConfig {
        public_key,
        private_key,
    })
}
