use crate::{PktLineIO, PktLineProcess};

// 正常ハンドシェイク
// Given: git-filter-client + version=2
// When: PktLineProcess::process()
// Then: git-filter-server + version=2 が返る
#[test]
fn git_filter_process_正常ハンドシェイク() {
    let reader = b"0016git-filter-client\n000eversion=2\n0000".as_slice();
    let mut writer = Vec::new();
    let mut process = PktLineProcess::with_pkt_io(PktLineIO::with_rw(reader, &mut writer)).unwrap();
    assert!(matches!(
        process.process(),
        Err(crate::Error::UnexpectedEof)
    )); // EOFになるはず
    let expected_output = b"0016git-filter-server\n000eversion=2\n0000";
    drop(process);
    assert_eq!(writer.as_slice(), expected_output);
}

// 異常ハンドシェイク（ヘッダ不正）
// Given: invalid-header + version=2
// When: PktLineProcess::process()
// Then: Err(InvalidHandshakePayload(_))
#[test]
fn git_filter_process_異常ハンドシェイク_ヘッダ不正() {
    let reader = b"0013invalid-header\n000eversion=2\n0000".as_slice();
    let mut writer = Vec::new();
    let mut process = PktLineProcess::with_pkt_io(PktLineIO::with_rw(reader, &mut writer)).unwrap();
    let result = process.process();
    assert!(matches!(
        result,
        Err(crate::Error::InvalidHandshakePayload(_))
    ));
}

// 異常ハンドシェイク（version不正）
// Given: git-filter-client + version=1
// When: PktLineProcess::process()
// Then: Err(InvalidVersion)
#[test]
fn git_filter_process_異常ハンドシェイク_version不正() {
    let reader = b"0016git-filter-client\n000eversion=1\n0000".as_slice();
    let mut writer = Vec::new();
    let mut process = PktLineProcess::with_pkt_io(PktLineIO::with_rw(reader, &mut writer)).unwrap();
    let result = process.process();
    assert!(matches!(result, Err(crate::Error::InvalidVersion)));
}

// unknown command
// Given: git-filter-client + version=2 + unknown-cmd
// When: PktLineProcess::process()
// Then: status=error
#[test]
fn git_filter_process_unknown_command() {
    // capabilityは何も指定しない
    let reader = b"0016git-filter-client\n000eversion=2\n000000000010unknown-cmd\n0000".as_slice();
    let mut writer = Vec::new();
    let mut process = PktLineProcess::with_pkt_io(PktLineIO::with_rw(reader, &mut writer)).unwrap();
    process.process().unwrap();
    let expected_output = b"0016git-filter-server\n000eversion=2\n000000000011status=error\n0000";
    drop(process);
    assert_eq!(writer.as_slice(), expected_output);
}
