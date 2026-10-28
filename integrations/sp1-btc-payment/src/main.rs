//! btc-pay-verify BUNDLE PAY_VKEY   -> btc_payment_v1 receipt JSON on stdout; exit 1 if rejected
//! btc-pay-verify pack PROOF_HEX STATEMENT_HEX OUT
fn reject(msg: &str) -> ! {
    let msg = msg.replace('\\', "\\\\").replace('"', "\\\"");
    println!("{{\"statement\":\"btc_payment_v1\",\"verified\":false,\"error\":\"{msg}\"}}");
    std::process::exit(1)
}

fn read_hex(path: &str) -> Vec<u8> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| reject(&format!("{path}: {e}")));
    let text = text.trim();
    hex::decode(text.strip_prefix("0x").unwrap_or(text))
        .unwrap_or_else(|e| reject(&format!("{path}: {e}")))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 5 && args[1] == "pack" {
        let bundle = sp1_btc_payment::pack(&read_hex(&args[2]), &read_hex(&args[3]))
            .unwrap_or_else(|e| reject(&e));
        std::fs::write(&args[4], bundle).unwrap_or_else(|e| reject(&e.to_string()));
        return;
    }
    if args.len() != 3 {
        reject("usage: btc-pay-verify BUNDLE PAY_VKEY | pack PROOF_HEX STATEMENT_HEX OUT");
    }
    let bundle = match std::fs::metadata(&args[1]) {
        Ok(m) if m.is_file() && m.len() == sp1_btc_payment::BUNDLE_LEN as u64 => {
            std::fs::read(&args[1]).unwrap_or_else(|e| reject(&e.to_string()))
        }
        Ok(_) => reject("not a BPG1 bundle"),
        Err(e) => reject(&format!("bundle: {e}")),
    };
    match sp1_btc_payment::verify_bundle(&bundle, &args[2]) {
        Ok(receipt) => println!("{receipt}"),
        Err(e) => reject(&e),
    }
}
