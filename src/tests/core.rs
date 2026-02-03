use std::{path::PathBuf, str::FromStr};

use crate::{encrypt, tests::util::TestRepository};

// Given: EncryptionPolicy の regex が ^src/、入力パス docs/readme.md
// When: encrypt()
// Then: 返るOIDが入力OIDと同一
#[test]
fn 暗号化対象外は素通し() {
    let mut repo = TestRepository::new();
    let input_path = PathBuf::from_str("docs/readme.md").unwrap();
    let input_oid = repo.context().repo().repo.blob(b"Hello, World!").unwrap();
    let output_oid = encrypt(repo.context_mut(), input_oid, input_path.as_os_str()).unwrap();
    assert_eq!(input_oid, output_oid);
}
