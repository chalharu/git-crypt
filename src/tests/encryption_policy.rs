use std::{path::PathBuf, rc::Rc, str::FromStr as _};

use pgp::{
    composed::{Deserializable, Message, SignedSecretKey},
    types::KeyDetails,
};

use crate::{
    EncryptionPolicy, GitConfig, encrypt,
    tests::util::{TestRepositoryBuilder, generate_keypair},
};

// regex未設定
// Given: encryption_path_regex=None, パス any/file.txt
// When: should_encrypt_file_path()
// Then: true
#[test]
fn encryption_policy_regex未設定() {
    let config = GitConfig {
        encryption_path_regex: None,
        public_key: "".into(),
        private_key: "".into(),
        encryption_key_id: None,
    };
    let mut policy = EncryptionPolicy::new(Rc::new(config));
    let path = PathBuf::from_str("any/file.txt").unwrap();
    assert!(
        policy
            .should_encrypt_file_path(path.as_os_str().as_encoded_bytes())
            .unwrap()
    );
}

// regex一致/不一致
// Given: regex=^src/, パス src/a.txt, docs/readme.md
// When: should_encrypt_file_path()
// Then: src/a.txt -> true, docs/readme.md -> false
#[test]
fn encryption_policy_regex一致不一致() {
    let config = GitConfig {
        encryption_path_regex: Some("^src/".into()),
        public_key: "".into(),
        private_key: "".into(),
        encryption_key_id: None,
    };
    let mut policy = EncryptionPolicy::new(Rc::new(config));
    let path_match = PathBuf::from_str("src/a.txt").unwrap();
    let path_not_match = PathBuf::from_str("docs/readme.md").unwrap();
    assert!(
        policy
            .should_encrypt_file_path(path_match.as_os_str().as_encoded_bytes())
            .unwrap()
    );
    assert!(
        !policy
            .should_encrypt_file_path(path_not_match.as_os_str().as_encoded_bytes())
            .unwrap()
    );
}

// key_id未設定
// Given: encryption_key_id=None, 暗号化済みメッセージ
// When: is_encrypted_for_configured_key()
// Then: true
#[test]
fn encryption_policy_key_id未設定() {
    // 暗号化済みメッセージを生成
    let mut repo = TestRepositoryBuilder::new().build();
    let input_path = PathBuf::from_str("src/a.txt").unwrap();
    let input_content = b"hello\n";
    let input_oid = repo.context().repo.repo.blob(input_content).unwrap();
    let encrypted_oid = encrypt(repo.context_mut(), input_oid, input_path.as_os_str()).unwrap();
    let encrypt_data = repo
        .context()
        .repo
        .repo
        .find_blob(encrypted_oid)
        .unwrap()
        .content()
        .to_vec();
    let (encrypted_message, _) = Message::from_armor(encrypt_data.as_slice()).unwrap();

    let config = GitConfig {
        encryption_path_regex: None,
        public_key: "".into(),
        private_key: "".into(),
        encryption_key_id: None,
    };
    let mut policy = EncryptionPolicy::new(Rc::new(config));
    assert!(
        policy
            .is_encrypted_for_configured_key(&encrypted_message)
            .unwrap()
    );
}

// key_id一致/不一致
// Given: encryption_key_id=TEST_KEY_ID, 暗号化済みメッセージ(TEST_KEY_ID, OTHER_KEY_ID)
// When: is_encrypted_for_configured_key()
// Then: TEST_KEY_ID -> true, OTHER_KEY_ID -> false
#[test]
fn encryption_policy_key_id一致不一致() {
    let keypair = generate_keypair();
    let key = SignedSecretKey::from_bytes(keypair.0.as_slice()).unwrap();
    let key_id = key.key_id().to_string();

    // 暗号化済みメッセージを生成

    // TEST_KEY_ID
    let mut repo = TestRepositoryBuilder::new()
        .with_private_key_data(keypair.0.clone())
        .with_public_key_data(keypair.1.clone())
        .build();
    let input_path = PathBuf::from_str("src/a.txt").unwrap();
    let input_content = b"hello\n";
    let input_oid = repo.context().repo.repo.blob(input_content).unwrap();
    let encrypted_oid = encrypt(repo.context_mut(), input_oid, input_path.as_os_str()).unwrap();
    let encrypt_data = repo
        .context()
        .repo
        .repo
        .find_blob(encrypted_oid)
        .unwrap()
        .content()
        .to_vec();
    let (encrypted_message_test_key_id, _) = Message::from_armor(encrypt_data.as_slice()).unwrap();

    // OTHER_KEY_ID
    let mut repo = TestRepositoryBuilder::new().build();
    let input_oid = repo.context().repo.repo.blob(input_content).unwrap();
    let encrypted_oid = encrypt(repo.context_mut(), input_oid, input_path.as_os_str()).unwrap();
    let encrypt_data = repo
        .context()
        .repo
        .repo
        .find_blob(encrypted_oid)
        .unwrap()
        .content()
        .to_vec();
    let (encrypted_message_other_key_id, _) = Message::from_armor(encrypt_data.as_slice()).unwrap();

    let config = GitConfig {
        encryption_path_regex: None,
        public_key: "".into(),
        private_key: "".into(),
        encryption_key_id: Some(key_id.clone()),
    };
    let mut policy = EncryptionPolicy::new(Rc::new(config));
    assert!(
        policy
            .is_encrypted_for_configured_key(&encrypted_message_test_key_id)
            .unwrap()
    );
    assert!(
        !policy
            .is_encrypted_for_configured_key(&encrypted_message_other_key_id)
            .unwrap()
    );
}
