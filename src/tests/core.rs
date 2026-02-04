use std::{path::PathBuf, str::FromStr};

use crate::{
    decrypt, encrypt,
    tests::util::{TestRepositoryBuilder, generate_keypair},
};

// 平文→暗号化→復号で一致
// Given: 平文 b"hello\n", 対象パス src/a.txt
// When.1: encrypt()
// Then.1: 返るOIDが平文とは異なる
// When.2: decrypt()
// Then.2: 返る内容が平文と同一
#[test]
fn encrypt_decrypt_正常系() {
    let mut repo = TestRepositoryBuilder::new().build();
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

// 暗号化済み再暗号化防止
// Given: 暗号化済みOID、対象パス src/a.txt
// When: encrypt()
// Then: 返るOIDが入力OIDと同一
#[test]
fn encrypt_暗号化済み再暗号化防止() {
    let keypair = generate_keypair();
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

    // キャッシュの影響を受けないようにするためリポジトリを新規作成しなおす
    let mut repo_new = TestRepositoryBuilder::new()
        .with_private_key_data(keypair.0)
        .with_public_key_data(keypair.1)
        .build();
    let encrypted_oid = repo_new.context().repo.repo.blob(&encrypt_data).unwrap();
    let re_encrypted_oid = encrypt(
        repo_new.context_mut(),
        encrypted_oid,
        input_path.as_os_str(),
    )
    .unwrap();

    assert_eq!(encrypted_oid, re_encrypted_oid);
}

// 暗号化対象外は素通し
// Given: EncryptionPolicy の regex が ^src/、入力パス docs/readme.md
// When: encrypt()
// Then: 返るOIDが入力OIDと同一
#[test]
fn encrypt_暗号化対象外は素通し() {
    let mut repo = TestRepositoryBuilder::new()
        .with_encryption_path_regex("^src/".into())
        .build();
    let input_path = PathBuf::from_str("docs/readme.md").unwrap();
    let input_oid = repo.context().repo.repo.blob(b"Hello, World!").unwrap();
    let output_oid = encrypt(repo.context_mut(), input_oid, input_path.as_os_str()).unwrap();
    assert_eq!(input_oid, output_oid);
}

// キーID不一致の復号は素通し
// Given: 暗号化済みOID
// When: decrypt() を別キーIDで実行(秘密鍵は持っている)
// Then: 返るOIDが入力OIDと同一
#[test]
#[allow(non_snake_case)]
fn decrypt_キーID不一致の復号は素通し() {
    let keypair = generate_keypair();
    let mut repo_encrypt = TestRepositoryBuilder::new()
        .with_private_key_data(keypair.0.clone())
        .with_public_key_data(keypair.1.clone())
        .build();
    let input_path = PathBuf::from_str("src/a.txt").unwrap();
    let input_content = b"hello\n";
    let input_oid = repo_encrypt
        .context()
        .repo
        .repo
        .blob(input_content)
        .unwrap();
    let encrypted_oid = encrypt(
        repo_encrypt.context_mut(),
        input_oid,
        input_path.as_os_str(),
    )
    .unwrap();

    let mut repo_decrypt = TestRepositoryBuilder::new()
        .with_private_key_data(keypair.0.clone())
        .with_public_key_data(keypair.1.clone())
        .with_encryption_key_id("DEADBEAF".into()) // 適当なキーID
        .build();
    let output_oid = decrypt(
        repo_decrypt.context_mut(),
        encrypted_oid,
        input_path.as_os_str().as_encoded_bytes(),
    )
    .unwrap();
    assert_eq!(encrypted_oid, output_oid);
}

// 破損PGPは素通し
// Given: 破損PGPデータ
// When: decrypt()
// Then: 返るOIDが入力OIDと同一
#[test]
#[allow(non_snake_case)]
fn decrypt_破損PGPは素通し() {
    let mut repo = TestRepositoryBuilder::new().build();
    let input_path = PathBuf::from_str("src/a.txt").unwrap();
    let corrupt_pgp_data =
        b"-----BEGIN PGP MESSAGE-----\ncorrupt data\n-----END PGP MESSAGE-----\n";
    let input_oid = repo.context().repo.repo.blob(corrupt_pgp_data).unwrap();
    let output_oid = decrypt(
        repo.context_mut(),
        input_oid,
        input_path.as_os_str().as_encoded_bytes(),
    )
    .unwrap();
    assert_eq!(input_oid, output_oid);
}

// MissingKeyは素通し
// Given: 公開鍵Aで暗号化したデータ, 秘密鍵Bのみ
// When: decrypt()
// Then: 返るOIDが入力OIDと同一
#[test]
fn decrypt_キー不一致の復号は素通し() {
    let keypair_a = generate_keypair();
    let keypair_b = generate_keypair();
    let mut repo_encrypt = TestRepositoryBuilder::new()
        .with_private_key_data(keypair_a.0.clone())
        .with_public_key_data(keypair_a.1.clone())
        .build();
    let input_path = PathBuf::from_str("src/a.txt").unwrap();
    let input_content = b"hello\n";
    let input_oid = repo_encrypt
        .context()
        .repo
        .repo
        .blob(input_content)
        .unwrap();
    let encrypted_oid = encrypt(
        repo_encrypt.context_mut(),
        input_oid,
        input_path.as_os_str(),
    )
    .unwrap();

    let mut repo_decrypt = TestRepositoryBuilder::new()
        .with_private_key_data(keypair_b.0)
        .with_public_key_data(keypair_b.1)
        .build();
    let output_oid = decrypt(
        repo_decrypt.context_mut(),
        encrypted_oid,
        input_path.as_os_str().as_encoded_bytes(),
    )
    .unwrap();
    assert_eq!(encrypted_oid, output_oid);
}
