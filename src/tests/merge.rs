use std::{path::PathBuf, str::FromStr as _};

use crate::{clean, merge, smudge, tests::util::TestRepositoryBuilder};

// 競合なしのマージ
// Given: base, local, remote 全て別々の変更箇所
// When: merge()
// Then: マージ結果が期待通りで競合なし
#[test]
fn merge_競合なし() {
    let repo = TestRepositoryBuilder::new().build();

    let base_content = b"line1\nline2\nline3\nline4\nline5\n";
    let local_content = b"line1\nline2 modified\nline3\nline4\nline5\n";
    let remote_content = b"line1\nline2\nline3\nline4 modified\nline5\n";

    let base_path = repo.path().join("base.txt");
    let local_path = repo.path().join("local.txt");
    let remote_path = repo.path().join("remote.txt");

    let test_file_path = PathBuf::from_str("test.txt").unwrap();

    clean(
        &mut base_content.as_slice(),
        &mut std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&base_path)
            .unwrap(),
        test_file_path.as_os_str(),
        repo.path(),
    )
    .unwrap();

    clean(
        &mut local_content.as_slice(),
        &mut std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&local_path)
            .unwrap(),
        test_file_path.as_os_str(),
        repo.path(),
    )
    .unwrap();

    clean(
        &mut remote_content.as_slice(),
        &mut std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&remote_path)
            .unwrap(),
        test_file_path.as_os_str(),
        repo.path(),
    )
    .unwrap();

    let merge_status = merge(
        &base_path,
        &local_path,
        &remote_path,
        None,
        test_file_path.as_os_str(),
        repo.path(),
    )
    .unwrap();

    // マージ結果確認
    let expected_merged_content = b"line1\nline2 modified\nline3\nline4 modified\nline5\n";
    let mut merged_content = Vec::new();
    smudge(
        &mut std::fs::File::open(&local_path).unwrap(),
        &mut merged_content,
        test_file_path.as_os_str(),
        repo.path(),
    )
    .unwrap();

    // 競合なし
    assert!(merge_status);
    assert_eq!(merged_content.as_slice(), expected_merged_content);
}

// 競合なし(非暗号化パス)のマージ
// Given: base, local, remote 全て別々の変更箇所, 非暗号化パス
// When: merge()
// Then: マージ結果が期待通りで競合なし
#[test]
fn merge_競合なし_非暗号化パス() {
    let repo = TestRepositoryBuilder::new()
        .with_encryption_path_regex("^secret/*".into())
        .build();

    let base_content = b"line1\nline2\nline3\nline4\nline5\n";
    let local_content = b"line1\nline2 modified\nline3\nline4\nline5\n";
    let remote_content = b"line1\nline2\nline3\nline4 modified\nline5\n";

    let base_path = repo.path().join("base.txt");
    let local_path = repo.path().join("local.txt");
    let remote_path = repo.path().join("remote.txt");

    let test_file_path = PathBuf::from_str("test.txt").unwrap();

    clean(
        &mut base_content.as_slice(),
        &mut std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&base_path)
            .unwrap(),
        test_file_path.as_os_str(),
        repo.path(),
    )
    .unwrap();

    clean(
        &mut local_content.as_slice(),
        &mut std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&local_path)
            .unwrap(),
        test_file_path.as_os_str(),
        repo.path(),
    )
    .unwrap();

    clean(
        &mut remote_content.as_slice(),
        &mut std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&remote_path)
            .unwrap(),
        test_file_path.as_os_str(),
        repo.path(),
    )
    .unwrap();

    let merge_status = merge(
        &base_path,
        &local_path,
        &remote_path,
        None,
        test_file_path.as_os_str(),
        repo.path(),
    )
    .unwrap();

    // マージ結果確認
    let expected_merged_content = b"line1\nline2 modified\nline3\nline4 modified\nline5\n";
    let merged_content = std::fs::read(&local_path).unwrap();

    // 競合なし
    assert!(merge_status);
    assert_eq!(merged_content.as_slice(), expected_merged_content);
}

// 競合ありのマージ
// Given: base, local, remote 全て別々の変更箇所
// When: merge()
// Then: マージ結果が期待通りで競合あり
#[test]
fn merge_競合あり() {
    let repo = TestRepositoryBuilder::new().build();

    let base_content = b"line1\noriginal\nline3\n";
    let local_content = b"line1\nlocal change\nline3\n";
    let remote_content = b"line1\nremote change\nline3\n";

    let base_path = repo.path().join("base.txt");
    let local_path = repo.path().join("local.txt");
    let remote_path = repo.path().join("remote.txt");

    let test_file_path = PathBuf::from_str("test.txt").unwrap();

    clean(
        &mut base_content.as_slice(),
        &mut std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&base_path)
            .unwrap(),
        test_file_path.as_os_str(),
        repo.path(),
    )
    .unwrap();

    clean(
        &mut local_content.as_slice(),
        &mut std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&local_path)
            .unwrap(),
        test_file_path.as_os_str(),
        repo.path(),
    )
    .unwrap();

    clean(
        &mut remote_content.as_slice(),
        &mut std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&remote_path)
            .unwrap(),
        test_file_path.as_os_str(),
        repo.path(),
    )
    .unwrap();

    let merge_status = merge(
        &base_path,
        &local_path,
        &remote_path,
        None,
        test_file_path.as_os_str(),
        repo.path(),
    )
    .unwrap();

    // 競合あり
    assert!(!merge_status);
}

// local==remote
// Given: base, local, remote で local と remote が同一
// When: merge()
// Then: 競合なしで local の内容が維持される
#[test]
fn merge_local_equals_remote() {
    let repo = TestRepositoryBuilder::new().build();

    let base_content = b"line1";
    let local_content = b"line1 modified";
    let remote_content = b"line1 modified";

    let base_path = repo.path().join("base.txt");
    let local_path = repo.path().join("local.txt");
    let remote_path = repo.path().join("remote.txt");

    let test_file_path = PathBuf::from_str("test.txt").unwrap();

    clean(
        &mut base_content.as_slice(),
        &mut std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&base_path)
            .unwrap(),
        test_file_path.as_os_str(),
        repo.path(),
    )
    .unwrap();

    clean(
        &mut local_content.as_slice(),
        &mut std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&local_path)
            .unwrap(),
        test_file_path.as_os_str(),
        repo.path(),
    )
    .unwrap();

    clean(
        &mut remote_content.as_slice(),
        &mut std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&remote_path)
            .unwrap(),
        test_file_path.as_os_str(),
        repo.path(),
    )
    .unwrap();

    let merge_status = merge(
        &base_path,
        &local_path,
        &remote_path,
        None,
        test_file_path.as_os_str(),
        repo.path(),
    )
    .unwrap();

    // マージ結果確認
    let expected_merged_content = b"line1 modified";
    let mut merged_content = Vec::new();
    smudge(
        &mut std::fs::File::open(&local_path).unwrap(),
        &mut merged_content,
        test_file_path.as_os_str(),
        repo.path(),
    )
    .unwrap();

    // 競合なし
    assert!(merge_status);
    assert_eq!(merged_content.as_slice(), expected_merged_content);
}

// base==local
// Given: base, local, remote で base と local が同一
// When: merge()
// Then: 競合なしで remote の内容が反映される
#[test]
fn merge_base_equals_local() {
    let repo = TestRepositoryBuilder::new().build();

    let base_content = b"line1";
    let local_content = b"line1";
    let remote_content = b"line1 modified";

    let base_path = repo.path().join("base.txt");
    let local_path = repo.path().join("local.txt");
    let remote_path = repo.path().join("remote.txt");

    let test_file_path = PathBuf::from_str("test.txt").unwrap();

    clean(
        &mut base_content.as_slice(),
        &mut std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&base_path)
            .unwrap(),
        test_file_path.as_os_str(),
        repo.path(),
    )
    .unwrap();

    clean(
        &mut local_content.as_slice(),
        &mut std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&local_path)
            .unwrap(),
        test_file_path.as_os_str(),
        repo.path(),
    )
    .unwrap();

    clean(
        &mut remote_content.as_slice(),
        &mut std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&remote_path)
            .unwrap(),
        test_file_path.as_os_str(),
        repo.path(),
    )
    .unwrap();

    let merge_status = merge(
        &base_path,
        &local_path,
        &remote_path,
        None,
        test_file_path.as_os_str(),
        repo.path(),
    )
    .unwrap();

    // マージ結果確認
    let expected_merged_content = b"line1 modified";
    let mut merged_content = Vec::new();
    smudge(
        &mut std::fs::File::open(&local_path).unwrap(),
        &mut merged_content,
        test_file_path.as_os_str(),
        repo.path(),
    )
    .unwrap();

    // 競合なし
    assert!(merge_status);
    assert_eq!(merged_content.as_slice(), expected_merged_content);
}

// base==remote
// Given: base, local, remote で base と remote が同一
// When: merge()
// Then: 競合なしで local の内容が維持される
#[test]
fn merge_base_equals_remote() {
    let repo = TestRepositoryBuilder::new().build();

    let base_content = b"line1";
    let local_content = b"line1 modified";
    let remote_content = b"line1";

    let base_path = repo.path().join("base.txt");
    let local_path = repo.path().join("local.txt");
    let remote_path = repo.path().join("remote.txt");

    let test_file_path = PathBuf::from_str("test.txt").unwrap();

    clean(
        &mut base_content.as_slice(),
        &mut std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&base_path)
            .unwrap(),
        test_file_path.as_os_str(),
        repo.path(),
    )
    .unwrap();

    clean(
        &mut local_content.as_slice(),
        &mut std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&local_path)
            .unwrap(),
        test_file_path.as_os_str(),
        repo.path(),
    )
    .unwrap();

    clean(
        &mut remote_content.as_slice(),
        &mut std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&remote_path)
            .unwrap(),
        test_file_path.as_os_str(),
        repo.path(),
    )
    .unwrap();

    let merge_status = merge(
        &base_path,
        &local_path,
        &remote_path,
        None,
        test_file_path.as_os_str(),
        repo.path(),
    )
    .unwrap();

    // マージ結果確認
    let expected_merged_content = b"line1 modified";
    let mut merged_content = Vec::new();
    smudge(
        &mut std::fs::File::open(&local_path).unwrap(),
        &mut merged_content,
        test_file_path.as_os_str(),
        repo.path(),
    )
    .unwrap();

    // 競合なし
    assert!(merge_status);
    assert_eq!(merged_content.as_slice(), expected_merged_content);
}
