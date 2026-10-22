use rust_bitcoin_zk_adapter::op_return::{decode_op_return, DecodeError};

#[test]
fn direct_and_pushdata_encodings_preserve_opaque_bytes() {
    let content = b"\x00\xffraw-app-data";
    for mut script in [
        vec![0x6a, content.len() as u8],
        vec![0x6a, 0x4c, content.len() as u8],
        vec![0x6a, 0x4d, content.len() as u8, 0],
        vec![0x6a, 0x4e, content.len() as u8, 0, 0, 0],
    ] {
        script.extend_from_slice(content);
        assert_eq!(decode_op_return(&script).unwrap(), content);
    }
}
#[test]
fn concatenates_multiple_pushes_without_protocol_interpretation() {
    let script = b"\x6a\x02zk\x05proof\x00";
    assert_eq!(decode_op_return(script).unwrap(), b"zkproof");
}
#[test]
fn preserves_unknown_marker_without_filtering() {
    let data = decode_op_return(b"\x6a\x06abcd12").unwrap();
    assert_eq!(data, b"abcd12");
}
#[test]
fn malformed_scripts_fail_closed() {
    let cases = [
        (vec![0x00, 0x6a, 0x01, b'x'], DecodeError::NotOpReturn),
        (vec![0x6a, 0x4c], DecodeError::TruncatedLength),
        (vec![0x6a, 0x4d, 0x01], DecodeError::TruncatedLength),
        (vec![0x6a, 0x4e, 0x01, 0, 0], DecodeError::TruncatedLength),
        (vec![0x6a, 0x03, b'a', b'b'], DecodeError::TruncatedData),
        (vec![0x6a, 0x51], DecodeError::UnsupportedOpcode(0x51)),
    ];
    for (script, expected) in cases {
        assert_eq!(decode_op_return(&script), Err(expected));
    }
}
#[test]
fn resource_guards_trigger() {
    let mut huge = vec![0x6a, 0x4e];
    huge.extend_from_slice(&100_001u32.to_le_bytes());
    assert_eq!(decode_op_return(&huge), Err(DecodeError::DataTooLarge));
    let mut pushes = vec![0x6a];
    pushes.extend_from_slice(&[0; 1_025]);
    assert_eq!(decode_op_return(&pushes), Err(DecodeError::TooManyPushes));
    assert_eq!(
        decode_op_return(&vec![0x6a; 100_001]),
        Err(DecodeError::ScriptTooLarge)
    );
}
#[test]
fn empty_op_return() {
    assert_eq!(decode_op_return(&[0x6a]).unwrap(), Vec::<u8>::new());
    assert_eq!(decode_op_return(&[0x6a, 0]).unwrap(), Vec::<u8>::new());
}
