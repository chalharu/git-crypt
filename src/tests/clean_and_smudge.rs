use std::{path::PathBuf, str::FromStr as _};

use crate::{clean, smudge, tests::util::TestRepositoryBuilder};

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
