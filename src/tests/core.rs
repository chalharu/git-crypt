use std::{path::PathBuf, str::FromStr};

use crate::{decrypt, encrypt, tests::util::TestRepository};

// Given: 平文 b"hello\n", 対象パス src/a.txt
// When.1: encrypt()
// Then.1: 返るOIDが平文とは異なる
// When.2: decrypt()
// Then.2: 返る内容が平文と同一
#[test]
fn encrypt_decrypt_正常系() {
    let mut repo = TestRepository::new();
    let input_path = PathBuf::from_str("src/a.txt").unwrap();
    let input_content = b"hello\n";
    let input_oid = repo.context().repo.repo.blob(input_content).unwrap();
    let encrypted_oid = encrypt(repo.context_mut(), input_oid, input_path.as_os_str()).unwrap();
    assert_ne!(input_oid, encrypted_oid);

    let decrypted_content = decrypt(
        repo.context_mut(),
        encrypted_oid,
        input_path.as_os_str().as_encoded_bytes(),
    )
    .unwrap();
    assert_eq!(input_oid, decrypted_content);
}

// Given: EncryptionPolicy の regex が ^src/、入力パス docs/readme.md
// When: encrypt()
// Then: 返るOIDが入力OIDと同一
#[test]
fn encrypt_暗号化対象外は素通し() {
    let mut repo = TestRepository::new();
    let input_path = PathBuf::from_str("docs/readme.md").unwrap();
    let input_oid = repo.context().repo.repo.blob(b"Hello, World!").unwrap();
    let output_oid = encrypt(repo.context_mut(), input_oid, input_path.as_os_str()).unwrap();
    assert_eq!(input_oid, output_oid);
}
