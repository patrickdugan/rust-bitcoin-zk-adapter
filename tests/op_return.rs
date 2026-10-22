use rust_bitcoin_zk_adapter::op_return::{
    decode_op_return, decode_tradelayer_envelope, DecodeError, TradeLayerEnvelope,
};

#[test]
fn all_push_types_preserve_payload() {
    let expected = b"tl20;;z;2s";
    for mut script in [
        vec![0x6a, expected.len() as u8],
        vec![0x6a, 0x4c, expected.len() as u8],
        vec![0x6a, 0x4d, expected.len() as u8, 0],
        vec![0x6a, 0x4e, expected.len() as u8, 0, 0, 0],
    ] {
        script.extend_from_slice(expected);
        let data = decode_op_return(&script).unwrap();
        assert_eq!(data, expected);
        assert_eq!(
            decode_tradelayer_envelope(&data).unwrap(),
            Some(TradeLayerEnvelope { tx_type: 2, body: "0;;z;2s".into() })
        );
    }
}
#[test]
fn concatenates_separate_pushes() {
    let script = b"\x6a\x02tl\x0320;\x03z;2";
    let data = decode_op_return(script).unwrap();
    assert_eq!(data, b"tl20;z;2");
    let env = decode_tradelayer_envelope(&data).unwrap().unwrap();
    assert_eq!(env.tx_type, 2);
    assert_eq!(env.body, "0;z;2");
}
#[test]
fn marker_must_be_at_payload_start() {
    let data = decode_op_return(b"\x6a\x06xxxtl2").unwrap();
    assert_eq!(decode_tradelayer_envelope(&data).unwrap(), None);
    assert_eq!(decode_tradelayer_envelope(b"omni2").unwrap(), None);
    assert_eq!(decode_tradelayer_envelope(b"tl"), Err(DecodeError::MissingTransactionType));
    assert_eq!(decode_tradelayer_envelope(b"tlAfoo"), Err(DecodeError::InvalidTransactionType(b'A')));
    assert_eq!(decode_tradelayer_envelope(b"tl2\x00bad"), Err(DecodeError::NonPrintablePayload));
}
#[test]
fn malformed_scripts_fail_closed() {
    let cases = [
        (vec![0x00,0x6a,0x01,b'x'], DecodeError::NotOpReturn),
        (vec![0x6a,0x4c], DecodeError::TruncatedLength),
        (vec![0x6a,0x4d,0x01], DecodeError::TruncatedLength),
        (vec![0x6a,0x4e,0x01,0,0], DecodeError::TruncatedLength),
        (vec![0x6a,0x03,b't',b'l'], DecodeError::TruncatedData),
        (vec![0x6a,0x51], DecodeError::UnsupportedOpcode(0x51)),
    ];
    for (script, expected) in cases {
        assert_eq!(decode_op_return(&script), Err(expected));
    }
}
#[test]
fn resource_guards_trigger() {
    let mut huge = vec![0x6a,0x4e];
    huge.extend_from_slice(&100_001u32.to_le_bytes());
    assert_eq!(decode_op_return(&huge), Err(DecodeError::DataTooLarge));
    let mut pushes = vec![0x6a];
    pushes.extend_from_slice(&[0;1_025]);
    assert_eq!(decode_op_return(&pushes), Err(DecodeError::TooManyPushes));
    assert_eq!(decode_op_return(&vec![0x6a;100_001]), Err(DecodeError::ScriptTooLarge));
}
#[test]
fn empty_op_return() {
    assert_eq!(decode_op_return(&[0x6a]).unwrap(), Vec::<u8>::new());
    assert_eq!(decode_op_return(&[0x6a,0]).unwrap(), Vec::<u8>::new());
}
