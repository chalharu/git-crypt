use std::path::Path;

use git2::Repository;
use pgp::{composed::SecretKeyParamsBuilder, ser::Serialize};
use rand::thread_rng;
use tempfile::TempDir;

use crate::{Context, GitConfig, GitRepository};

pub struct TestRepository {
    tempdir: TempDir,
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

        std::fs::write(
            tempdir.path().join("private.gpg"),
            signed_private_key.to_bytes().unwrap(),
        )
        .unwrap();
        std::fs::write(
            tempdir.path().join("public.gpg"),
            signed_public_key.to_bytes().unwrap(),
        )
        .unwrap();

        let mut config = repo.config().unwrap();
        config
            .set_str(
                &GitConfig::combine_section_key(GitConfig::PUBLIC_KEY),
                "public.gpg",
            )
            .unwrap();
        config
            .set_str(
                &GitConfig::combine_section_key(GitConfig::PRIVATE_KEY),
                "private.gpg",
            )
            .unwrap();

        Self {
            tempdir,
            context: Context::with_repo(GitRepository { repo }).unwrap(),
        }
    }

    pub fn path(&self) -> &Path {
        self.tempdir.path()
    }

    pub fn context(&self) -> &Context {
        &self.context
    }

    pub fn context_mut(&mut self) -> &mut Context {
        &mut self.context
    }
}
