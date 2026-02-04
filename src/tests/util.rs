use git2::Repository;
use pgp::{composed::SecretKeyParamsBuilder, ser::Serialize};
use rand::thread_rng;
use tempfile::TempDir;

use crate::{Context, GitConfig, GitRepository};

pub struct TestRepository {
    _tempdir: TempDir,
    context: Context,
}

impl TestRepository {
    pub fn new() -> Self {
        let tempdir = TempDir::new().expect("Failed to create temp dir");
        let repo = Repository::init(tempdir.path()).expect("Failed to init repo");

        // キーを生成
        let private_key = SecretKeyParamsBuilder::default()
            .key_type(pgp::composed::KeyType::Rsa(2048))
            .can_certify(true)
            .can_encrypt(true)
            .primary_user_id("John Doe <jdoe@example.com>".to_string())
            .build()
            .expect("Failed to generate private key parameters")
            .generate(rand::thread_rng())
            .expect("Failed to generate private key");

        let signed_private_key = private_key
            .sign(thread_rng(), &"".into())
            .expect("Failed to sign private key");

        let signed_public_key = signed_private_key.signed_public_key();

        let private_key_path = tempdir.path().join("private.gpg");
        let public_key_path = tempdir.path().join("public.gpg");
        std::fs::write(&private_key_path, signed_private_key.to_bytes().unwrap()).unwrap();
        std::fs::write(&public_key_path, signed_public_key.to_bytes().unwrap()).unwrap();

        let mut config = repo.config().unwrap();
        config
            .set_str(
                &GitConfig::combine_section_key(GitConfig::PUBLIC_KEY),
                public_key_path.to_str().unwrap(),
            )
            .unwrap();
        config
            .set_str(
                &GitConfig::combine_section_key(GitConfig::PRIVATE_KEY),
                private_key_path.to_str().unwrap(),
            )
            .unwrap();
        config
            .set_str(
                &GitConfig::combine_section_key(GitConfig::ENCRYPTION_PATH_REGEX),
                "^src/",
            )
            .unwrap();

        Self {
            _tempdir: tempdir,
            context: Context::with_repo(GitRepository { repo }).unwrap(),
        }
    }

    pub fn context(&self) -> &Context {
        &self.context
    }

    pub fn context_mut(&mut self) -> &mut Context {
        &mut self.context
    }
}
