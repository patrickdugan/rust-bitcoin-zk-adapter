//! Real-proof acceptance for the NHC1 verifier CLI. Each run rebuilds the
//! 257 MB verifier key from the circuit shape (~1 min in release), so run
//! with `cargo test --release`.
use std::{path::PathBuf, process::Command};

const VK_SHA256: &str = "e46bb06929d701f1986d320e004e8ed744b0e5f74eb9f5e9c9bd0e2fe6ad1698";

fn fixture() -> Vec<u8> {
  std::fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/nova100.nhc1")).unwrap()
}

fn verify(bundle: &[u8], vk: Option<&std::path::Path>, name: &str) -> (bool, String) {
  let path = std::env::temp_dir().join(format!("nhc1-{}-{name}", std::process::id()));
  std::fs::write(&path, bundle).unwrap();
  let mut cmd = Command::new(env!("CARGO_BIN_EXE_btc-header-fold"));
  cmd.arg("verify-bundle").arg(&path);
  if let Some(vk) = vk {
    cmd.arg("--vk").arg(vk);
  }
  let out = cmd.output().unwrap();
  std::fs::remove_file(&path).unwrap();
  (out.status.success(), String::from_utf8(out.stdout).unwrap())
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release only: Nova verification is slow unoptimized")]
fn real_100_header_proof_verifies_and_tampering_is_rejected() {
  let vk = std::env::temp_dir().join(format!("nhc1-vk-{}", std::process::id()));
  let out = Command::new(env!("CARGO_BIN_EXE_btc-header-fold"))
    .args(["vk-export", "10"])
    .arg(&vk)
    .output()
    .unwrap();
  assert!(String::from_utf8_lossy(&out.stdout).contains(VK_SHA256), "verifier key drifted");

  let good = fixture();
  let (ok, receipt) = verify(&good, Some(&vk), "good");
  assert!(ok, "{receipt}");
  for want in [
    "\"statement\":\"btc_header_chain_v1\"",
    &format!("\"vk_sha256\":\"{VK_SHA256}\""),
    "\"checkpoint\":{\"height\":1000,\"tip_hash\":\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"",
    "\"end\":{\"height\":1100,\"tip_hash\":\"000000009cd3f93cd2d843202155561eb773b2a7b7c97561ddef31e707f4eb4b\",\"chainwork\":\"0x44d044d044d\"}",
    "\"headers\":100",
    "\"verified\":true",
  ] {
    assert!(receipt.contains(want), "missing {want} in {receipt}");
  }

  // A flipped proof byte, a different checkpoint, a different step count and
  // a truncated bundle are each rejected with a non-zero exit.
  let mut proof = good.clone();
  let n = proof.len();
  proof[n - 100] ^= 1;
  let mut checkpoint = good.clone();
  checkpoint[12] ^= 1;
  let mut steps = good.clone();
  steps[4] = 9;
  for (name, bad) in [("proof", proof), ("checkpoint", checkpoint), ("steps", steps), ("short", good[..600].to_vec())] {
    let (ok, receipt) = verify(&bad, Some(&vk), name);
    assert!(!ok && receipt.contains("\"verified\":false"), "{name}: {receipt}");
  }
  std::fs::remove_file(vk).unwrap();
}
