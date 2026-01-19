use clap::{Parser, Subcommand};

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
    }
}
