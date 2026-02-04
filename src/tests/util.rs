use git2::Repository;
use pgp::{composed::SecretKeyParamsBuilder, ser::Serialize};
use rand::thread_rng;
use tempfile::TempDir;

use crate::{Context, GitConfig, GitRepository};

pub struct TestRepositoryBuilder {
    private_key_data: Option<Vec<u8>>,
    public_key_data: Option<Vec<u8>>,
    encryption_path_regex: Option<String>,
    encryption_key_id: Option<String>,
}

impl TestRepositoryBuilder {
    pub fn new() -> Self {
        Self {
            private_key_data: None,
            public_key_data: None,
            encryption_path_regex: None,
            encryption_key_id: None,
        }
    }

    pub fn with_private_key_data(mut self, data: Vec<u8>) -> Self {
        self.private_key_data = Some(data);
        self
    }

    pub fn with_public_key_data(mut self, data: Vec<u8>) -> Self {
        self.public_key_data = Some(data);
        self
    }

    pub fn with_encryption_path_regex(mut self, regex: String) -> Self {
        self.encryption_path_regex = Some(regex);
        self
    }

    pub fn with_encryption_key_id(mut self, key_id: String) -> Self {
        self.encryption_key_id = Some(key_id);
        self
    }

    pub fn build(self) -> TestRepository {
        let (private_key_data, public_key_data) =
            match (self.private_key_data, self.public_key_data) {
                (Some(priv_data), Some(pub_data)) => (priv_data, pub_data),
                _ => generate_keypair(),
            };

        let tempdir = TempDir::new().expect("Failed to create temp dir");
        let repo = Repository::init(tempdir.path()).expect("Failed to init repo");

        let private_key_path = tempdir.path().join("private.gpg");
        let public_key_path = tempdir.path().join("public.gpg");
        std::fs::write(&private_key_path, private_key_data).unwrap();
        std::fs::write(&public_key_path, public_key_data).unwrap();

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
        if let Some(regex) = self.encryption_path_regex {
            config
                .set_str(
                    &GitConfig::combine_section_key(GitConfig::ENCRYPTION_PATH_REGEX),
                    &regex,
                )
                .unwrap();
        }
        if let Some(key_id) = self.encryption_key_id {
            config
                .set_str(
                    &GitConfig::combine_section_key(GitConfig::ENCRYPTION_KEY_ID),
                    &key_id,
                )
                .unwrap();
        }

        TestRepository {
            _tempdir: tempdir,
            context: Context::with_repo(GitRepository { repo }).unwrap(),
        }
    }
}

pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
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
    (
        signed_private_key.to_bytes().unwrap(),
        signed_public_key.to_bytes().unwrap(),
    )
}

pub struct TestRepository {
    _tempdir: TempDir,
    context: Context,
}

impl TestRepository {
    pub fn context(&self) -> &Context {
        &self.context
    }

    pub fn context_mut(&mut self) -> &mut Context {
        &mut self.context
    }
}
