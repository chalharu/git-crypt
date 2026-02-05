use std::{path::PathBuf, str::FromStr as _};

use crate::{clean, tests::util::TestRepositoryBuilder, textconv};

// textconvでの復号化テスト
// Given: 暗号化済みファイル
// When: textconv()
// Then: 平文が返る
#[test]
fn textconv_復号化正常系() {
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

    let save_path = repo.path().join("temp_encrypted_blob");
    std::fs::write(&save_path, &encrypted_content).unwrap();
    let mut decrypted_content = Vec::new();

    textconv(&mut decrypted_content, save_path, repo.path()).unwrap();
    assert_eq!(input_content, decrypted_content.as_slice());
    drop(repo);
}
