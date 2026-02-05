use std::{path::PathBuf, str::FromStr as _};

use crate::{
    clean, smudge,
    tests::util::{TestRepositoryBuilder, generate_keypair},
};

// 平文→暗号化→復号で一致
// Given: 平文 b"hello\n", 対象パス src/a.txt
// When.1: clean()
// Then.1: 返る内容が平文とは異なる
// When.2: smudge()
// Then.2: 返る内容が平文と同一
#[test]
fn clean_smudge_正常系() {
    let repo = TestRepositoryBuilder::new().build();
    let input_path = PathBuf::from_str("src/a.txt").unwrap();
    let input_content = b"hello\n";
    let mut encrypted_content = Vec::new();

    clean(
        &mut input_content.as_slice(),
        &mut encrypted_content,
        input_path.as_os_str(),
        repo.path(),
    )
    .unwrap();
    assert_ne!(input_content, encrypted_content.as_slice());

    let mut decrypted_content = Vec::new();
    smudge(
        &mut encrypted_content.as_slice(),
        &mut decrypted_content,
        input_path.as_os_str(),
        repo.path(),
    )
    .unwrap();
    assert_eq!(input_content, decrypted_content.as_slice());
    drop(repo);
}

// 平文→暗号化→復号(キャッシュなし)で一致
// Given: 平文 b"hello\n", 対象パス src/a.txt
// When.1: clean()
// Then.1: 返る内容が平文とは異なる
// When.2: smudge()
// Then.2: 返る内容が平文と同一
#[test]
fn clean_smudge_復号キャッシュなし() {
    let keypair = generate_keypair();
    let repo = TestRepositoryBuilder::new()
        .with_private_key_data(keypair.0.clone())
        .with_public_key_data(keypair.1.clone())
        .build();
    let input_path = PathBuf::from_str("src/a.txt").unwrap();
    let input_content = b"hello\n";
    let mut encrypted_content = Vec::new();
    clean(
        &mut input_content.as_slice(),
        &mut encrypted_content,
        input_path.as_os_str(),
        repo.path(),
    )
    .unwrap();
    assert_ne!(input_content, encrypted_content.as_slice());
    drop(repo);

    // キャッシュの影響を受けないようにするためリポジトリを新規作成しなおす
    let repo = TestRepositoryBuilder::new()
        .with_private_key_data(keypair.0.clone())
        .with_public_key_data(keypair.1.clone())
        .build();
    let mut decrypted_content = Vec::new();
    smudge(
        &mut encrypted_content.as_slice(),
        &mut decrypted_content,
        input_path.as_os_str(),
        repo.path(),
    )
    .unwrap();
    assert_eq!(input_content, decrypted_content.as_slice());
}

// 平文→暗号化を同じリポジトリで2回実施で一致
// Given: 平文 b"hello\n", 対象パス src/a.txt
// When.1: clean()
// Then.1: 返る内容が平文とは異なる
// When.2: clean()
// Then.2: 返る内容が1回目の暗号化内容と同一
#[test]
fn clean_キャッシュあり2回目() {
    let keypair = generate_keypair();
    let repo = TestRepositoryBuilder::new()
        .with_private_key_data(keypair.0.clone())
        .with_public_key_data(keypair.1.clone())
        .build();
    let input_path = PathBuf::from_str("src/a.txt").unwrap();
    let input_content = b"hello\n";
    let mut encrypted_content = Vec::new();
    clean(
        &mut input_content.as_slice(),
        &mut encrypted_content,
        input_path.as_os_str(),
        repo.path(),
    )
    .unwrap();
    assert_ne!(input_content, encrypted_content.as_slice());

    let mut reencrypted_content = Vec::new();
    clean(
        &mut input_content.as_slice(),
        &mut reencrypted_content,
        input_path.as_os_str(),
        repo.path(),
    )
    .unwrap();
    assert_eq!(encrypted_content, reencrypted_content);
}
