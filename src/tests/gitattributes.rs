use std::collections::BTreeSet;

use crate::build_gitattributes;

// 既存filter削除/新規追加
// Given: 既存に * filter=x diff=x merge=x
// When: build_gitattributes()
// Then: 出力に * filter=<new> diff=<new> merge=<new> のみ
#[test]
fn gitattributes_既存filter削除新規追加() {
    let input = b"* filter=x diff=x merge=x";
    let output = build_gitattributes("new-filter", &BTreeSet::new(), input.as_slice()).unwrap();
    let expected_output = b"* filter=new-filter diff=new-filter merge=new-filter";

    assert_eq!(output.as_slice(), expected_output);
}

// 特殊ファイルは無効化属性
// Given: .gitattributes, .gitignore, .gitkeep
// When: build_gitattributes()
// Then: 各行に filter= diff= merge= 付与
#[test]
fn gitattributes_特殊ファイル無効化属性() {
    let special_files: BTreeSet<Vec<u8>> = vec![
        b".gitattributes".to_vec(),
        b".gitignore".to_vec(),
        b".gitkeep".to_vec(),
    ]
    .into_iter()
    .collect();
    let input = b"";
    let output = build_gitattributes("new", &special_files, input.as_slice()).unwrap();
    let expected_output = b"* filter=new diff=new merge=new\n.gitattributes filter= diff= merge=\n.gitignore filter= diff= merge=\n.gitkeep filter= diff= merge=";
    assert_eq!(output.as_slice(), expected_output);
}

// 重複排除
// Given: 同一パスを複数追加候補
// When: build_gitattributes()
// Then: 出力に重複行なし
#[test]
fn gitattributes_重複排除() {
    let special_files: BTreeSet<Vec<u8>> = vec![
        b".gitattributes".to_vec(),
        b".gitignore".to_vec(),
        b".gitattributes".to_vec(),
    ]
    .into_iter()
    .collect();
    let input = b"";
    let output = build_gitattributes("new", &special_files, input.as_slice()).unwrap();
    let expected_output = b"* filter=new diff=new merge=new\n.gitattributes filter= diff= merge=\n.gitignore filter= diff= merge=";
    assert_eq!(output.as_slice(), expected_output);
}
