//! Fold `steps` x `k` mainnet headers from a checkpoint with Nova (Pallas/Vesta,
//! IPA, no trusted setup), verify, and optionally compress with Spartan.
//!
//! btc-header-fold --start H --k K --steps N [--compress [--save DIR]] [--corrupt-nonce I]
//!   [--checkpoint-state FILE --headers-txt FILE]  (any-height checkpoint; default: early
//!                                                  mainnet headers under --data)
//! btc-header-fold verify DIR [--vk VK]        (DIR/proof.bin, z0.bin, steps.txt, k.txt)
//! btc-header-fold verify-bundle FILE [--vk VK] (an NHC1 bundle, see `pack`)
//!   Both print a btc_header_chain_v1 receipt as JSON; exit 1 if rejected.
//! btc-header-fold pack DIR OUT                 (DIR as written by --save -> NHC1 bundle)
//! btc-header-fold vk-export K OUT              (deterministic verifier key for fold width K)
use nova_header_chain::native::{early_chainwork, load_headers, Header, State};
use nova_header_chain::HeaderStep;
use nova_snark::{
  nova::{CompressedSNARK, PublicParams, RecursiveSNARK},
  provider::{ipa_pc, PallasEngine, VestaEngine},
  spartan::snark::RelaxedR1CSSNARK,
  traits::{snark::RelaxedR1CSSNARKTrait, Engine},
};
use ff::PrimeField;
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use std::time::Instant;

type E1 = PallasEngine;
type E2 = VestaEngine;
type S1 = RelaxedR1CSSNARK<E1, ipa_pc::EvaluationEngine<E1>>;
type S2 = RelaxedR1CSSNARK<E2, ipa_pc::EvaluationEngine<E2>>;
type C = HeaderStep;
type F1 = <E1 as Engine>::Scalar;

fn hwm_mib() -> String {
  std::fs::read_to_string("/proc/self/status")
    .ok()
    .and_then(|s| {
      s.lines()
        .find(|l| l.starts_with("VmHWM:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|kb| kb.parse::<u64>().ok())
    })
    .map(|kb| format!("{}", kb / 1024))
    .unwrap_or_else(|| "n/a".into())
}

/// A checkpoint at any height, from the 128-byte start state used by the SP1
/// chain programs: height u32 | hash 32 | chainwork 32 LE | nBits u32 |
/// time(height) u32 | time(epoch start) u32 | 11 | 11 timestamps u32
/// (oldest first). The verifier binds it through checkpoint_state_sha256
/// and Bitcoin Core checks its hash and chainwork.
fn sp1_checkpoint(b: &[u8]) -> State {
  assert!(b.len() == 128 && b[80] == 11, "not an SP1 chain start state");
  let u = |at: usize| u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
  let mut ts = [0u32; 11];
  for (i, t) in ts.iter_mut().enumerate() {
    *t = u(81 + 4 * i);
  }
  assert_eq!(ts[10], u(72), "last timestamp must be the checkpoint's");
  State {
    height: u(0),
    prev: b[4..36].try_into().unwrap(),
    chainwork: BigUint::from_bytes_le(&b[36..68]),
    epoch_bits: u(68),
    epoch_start: u(76),
    ts,
  }
}

/// "height hex" lines, each header hash-linked to its predecessor if present.
fn load_headers_txt(path: &std::path::Path) -> std::collections::BTreeMap<u32, Header> {
  let mut hs = std::collections::BTreeMap::new();
  for line in std::fs::read_to_string(path).expect("headers txt").lines().filter(|l| !l.trim().is_empty()) {
    let mut it = line.split_whitespace();
    let h: u32 = it.next().unwrap().parse().unwrap();
    let header: Header = hex::decode(it.next().unwrap()).unwrap().try_into().unwrap();
    hs.insert(h, header);
  }
  hs
}

fn arg(args: &[String], name: &str) -> Option<String> {
  args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn big(f: &F1) -> BigUint {
  BigUint::from_bytes_le(f.to_repr().as_ref())
}

fn z_bytes(z: &[F1]) -> Vec<u8> {
  z.iter().flat_map(|f| f.to_repr().as_ref().to_vec()).collect()
}

fn hex_be(v: &BigUint) -> String {
  format!("0x{}", v.to_str_radix(16))
}

/// Tip hash (display order) from the state's two 128-bit halves.
fn tip_display(lo: &F1, hi: &F1) -> String {
  let mut b = [0u8; 32];
  let (l, h) = (big(lo).to_bytes_le(), big(hi).to_bytes_le());
  b[..l.len()].copy_from_slice(&l);
  b[16..16 + h.len()].copy_from_slice(&h);
  b.reverse();
  hex::encode(b)
}

/// Bundle layout read by `verify-bundle` and written by `pack`:
/// b"NHC1" | steps u32 LE | k u32 LE | z0 (17 x 32-byte reprs) | compressed proof.
const BUNDLE_MAGIC: &[u8; 4] = b"NHC1";
const MAX_BUNDLE_BYTES: usize = 1 << 20;
const MAX_K: usize = 64;

fn rebuild_vk(k: usize) -> Vec<u8> {
  let shape = HeaderStep { headers: vec![[0u8; 80]; k] };
  let pp = PublicParams::<E1, E2, C>::setup(&shape, &*S1::ck_floor(), &*S2::ck_floor()).unwrap();
  let (_, vk) = CompressedSNARK::<E1, E2, C, S1, S2>::setup(&pp).unwrap();
  bincode::serialize(&vk).unwrap()
}

fn reject(msg: &str) -> i32 {
  let msg = msg.replace('\\', "\\\\").replace('"', "\\\"");
  println!("{{\"statement\":\"btc_header_chain_v1\",\"verified\":false,\"error\":\"{msg}\"}}");
  1
}

/// Split a bundle into (steps, k, z0, proof), bounding every field.
fn unpack(b: &[u8]) -> Result<(usize, usize, Vec<u8>, Vec<u8>), String> {
  if b.len() > MAX_BUNDLE_BYTES || b.len() < 12 + 17 * 32 || &b[..4] != BUNDLE_MAGIC {
    return Err("not an NHC1 bundle".into());
  }
  let steps = u32::from_le_bytes(b[4..8].try_into().unwrap()) as usize;
  let k = u32::from_le_bytes(b[8..12].try_into().unwrap()) as usize;
  if steps == 0 || k == 0 || k > MAX_K {
    return Err("bundle step count or fold width out of range".into());
  }
  Ok((steps, k, b[12..12 + 17 * 32].to_vec(), b[12 + 17 * 32..].to_vec()))
}

/// Verify a compressed proof and print its typed receipt. The verifier key
/// (~250 MB, mostly IPA generators) is a deterministic function of the
/// circuit shape: it is read from `vk_path` when given, else rebuilt; its
/// SHA-256 is reported so the caller can pin it.
fn verify(proof_b: Vec<u8>, z0_b: Vec<u8>, steps: usize, k: usize, vk_path: Option<&std::path::Path>) -> i32 {
  let vk_b = match vk_path {
    Some(p) => match std::fs::read(p) {
      Ok(b) => b,
      Err(e) => return reject(&format!("vk: {e}")),
    },
    None => rebuild_vk(k),
  };
  let vk: nova_snark::nova::VerifierKey<E1, E2, C, S1, S2> = match bincode::deserialize(&vk_b) {
    Ok(v) => v,
    Err(e) => return reject(&format!("vk decode: {e}")),
  };
  let snark: CompressedSNARK<E1, E2, C, S1, S2> = match bincode::deserialize(&proof_b) {
    Ok(v) => v,
    Err(e) => return reject(&format!("proof decode: {e}")),
  };
  if z0_b.len() != 17 * 32 {
    return reject("z0 must hold 17 field elements");
  }
  let mut z0 = Vec::with_capacity(17);
  for c in z0_b.chunks(32) {
    let mut r = <F1 as PrimeField>::Repr::default();
    r.as_mut().copy_from_slice(c);
    match Option::<F1>::from(F1::from_repr(r)) {
      Some(f) => z0.push(f),
      None => return reject("non-canonical field element in z0"),
    }
  }
  let t = Instant::now();
  let res = snark.verify(&vk, steps, &z0);
  let secs = t.elapsed().as_secs_f64();
  let sha = |b: &[u8]| hex::encode(Sha256::digest(b));
  match res {
    Ok(zn) => {
      println!(
        "{{\"statement\":\"btc_header_chain_v1\",\"verifier\":\"nova-snark 0.76.0 pallas/vesta ipa, spartan compressed\",\"vk_sha256\":\"{}\",\"proof_sha256\":\"{}\",\"checkpoint_state_sha256\":\"{}\",\"checkpoint\":{{\"height\":{},\"tip_hash\":\"{}\",\"chainwork\":\"{}\"}},\"end\":{{\"height\":{},\"tip_hash\":\"{}\",\"chainwork\":\"{}\"}},\"headers\":{},\"verify_seconds\":{:.3},\"verified\":true}}",
        sha(&vk_b), sha(&proof_b), sha(&z0_b),
        big(&z0[0]), tip_display(&z0[1], &z0[2]), hex_be(&big(&z0[3])),
        big(&zn[0]), tip_display(&zn[1], &zn[2]), hex_be(&big(&zn[3])),
        steps * k, secs
      );
      0
    }
    Err(e) => reject(&format!("{e:?}")),
  }
}

fn main() {
  let args: Vec<String> = std::env::args().collect();
  let vk_arg = arg(&args, "--vk").map(std::path::PathBuf::from);
  match args.get(1).map(String::as_str) {
    Some("verify") => {
      let dir = std::path::Path::new(args.get(2).expect("verify DIR"));
      let read = |n: &str| std::fs::read(dir.join(n)).unwrap_or_else(|e| panic!("{n}: {e}"));
      let num = |n: &str| String::from_utf8(read(n)).unwrap().trim().parse::<usize>().unwrap();
      let vk = vk_arg.or_else(|| Some(dir.join("vk.bin")).filter(|p| p.exists()));
      std::process::exit(verify(read("proof.bin"), read("z0.bin"), num("steps.txt"), num("k.txt"), vk.as_deref()));
    }
    Some("verify-bundle") => {
      let code = match std::fs::read(args.get(2).expect("verify-bundle FILE")) {
        Ok(b) => match unpack(&b) {
          Ok((steps, k, z0, proof)) => verify(proof, z0, steps, k, vk_arg.as_deref()),
          Err(e) => reject(&e),
        },
        Err(e) => reject(&format!("bundle: {e}")),
      };
      std::process::exit(code);
    }
    Some("pack") => {
      let dir = std::path::Path::new(args.get(2).expect("pack DIR OUT"));
      let read = |n: &str| std::fs::read(dir.join(n)).unwrap_or_else(|e| panic!("{n}: {e}"));
      let num = |n: &str| String::from_utf8(read(n)).unwrap().trim().parse::<u32>().unwrap();
      let mut b = BUNDLE_MAGIC.to_vec();
      b.extend(num("steps.txt").to_le_bytes());
      b.extend(num("k.txt").to_le_bytes());
      b.extend(read("z0.bin"));
      b.extend(read("proof.bin"));
      unpack(&b).expect("packed bundle must round-trip");
      std::fs::write(args.get(3).expect("pack DIR OUT"), &b).unwrap();
      return;
    }
    Some("vk-export") => {
      let k: usize = args.get(2).expect("vk-export K OUT").parse().unwrap();
      let b = rebuild_vk(k);
      std::fs::write(args.get(3).expect("vk-export K OUT"), &b).unwrap();
      println!("vk_sha256={}", hex::encode(Sha256::digest(&b)));
      return;
    }
    _ => {}
  }
  let start: u32 = arg(&args, "--start").map(|v| v.parse().unwrap()).unwrap_or(1000);
  let k: u32 = arg(&args, "--k").map(|v| v.parse().unwrap()).unwrap_or(1);
  let steps: u32 = arg(&args, "--steps").map(|v| v.parse().unwrap()).unwrap_or(1);
  let compress = args.iter().any(|a| a == "--compress");
  let corrupt: Option<u32> = arg(&args, "--corrupt-nonce").map(|v| v.parse().unwrap());
  let data = std::path::PathBuf::from(arg(&args, "--data").unwrap_or_else(|| "data".into()));

  let (hs, cp) = match (arg(&args, "--checkpoint-state"), arg(&args, "--headers-txt")) {
    (Some(state), Some(txt)) => {
      let hs = load_headers_txt(std::path::Path::new(&txt));
      let mut cp = sp1_checkpoint(&std::fs::read(state).expect("checkpoint state"));
      // Advance natively from the file's checkpoint to --start.
      while cp.height < start {
        cp = cp.apply(&hs[&(cp.height + 1)]).expect("headers before --start must be valid");
      }
      assert_eq!(cp.height, start, "--start precedes the checkpoint state");
      (hs, cp)
    }
    _ => {
      let hs = load_headers(&data);
      let cp = State::checkpoint(start, &hs, early_chainwork(start));
      (hs, cp)
    }
  };
  let mut state = cp.clone();
  let mut circuits = Vec::new();
  for s in 0..steps {
    let mut headers: Vec<Header> = (0..k).map(|i| hs[&(start + 1 + s * k + i)]).collect();
    for (i, h) in headers.iter_mut().enumerate() {
      if corrupt == Some(s * k + i as u32) {
        h[76] ^= 1;
      }
      // The native mirror rejects corrupted headers; keep going so the
      // prover/verifier sees them.
      state = state.apply(h).unwrap_or_else(|e| {
        eprintln!("native check rejects header {}: {e}", start + 1 + s * k + i as u32);
        state.clone()
      });
    }
    circuits.push(HeaderStep { headers });
  }
  println!("checkpoint {start}, {steps} step(s) x {k} header(s), compress={compress}");

  let t = Instant::now();
  let pp = PublicParams::<E1, E2, C>::setup(&circuits[0], &*S1::ck_floor(), &*S2::ck_floor()).unwrap();
  println!(
    "setup {:.2}s  constraints primary={} secondary={}  vars primary={}  hwm_mib={}",
    t.elapsed().as_secs_f64(),
    pp.num_constraints().0,
    pp.num_constraints().1,
    pp.num_variables().0,
    hwm_mib()
  );

  let z0 = cp.to_z::<F1>();
  let t_all = Instant::now();
  let mut rs = RecursiveSNARK::<E1, E2, C>::new(&pp, &circuits[0], &z0).unwrap();
  for (i, c) in circuits.iter().enumerate() {
    let t = Instant::now();
    rs.prove_step(&pp, c).unwrap();
    println!("prove_step {i}: {:.2}s  hwm_mib={}", t.elapsed().as_secs_f64(), hwm_mib());
  }
  let fold_s = t_all.elapsed().as_secs_f64();
  let t = Instant::now();
  let res = rs.verify(&pp, steps as usize, &z0);
  let verify_s = t.elapsed().as_secs_f64();
  let accepted = match &res {
    Ok(z) => *z == state.to_z::<F1>(),
    Err(_) => false,
  };
  println!(
    "recursive verify {:.3}s: {}  (outputs match native final state: {})",
    verify_s,
    if res.is_ok() { "ok" } else { "REJECTED" },
    accepted
  );
  if let Err(e) = &res {
    println!("verify error: {e:?}");
  }

  let mut summary = format!(
    "SUMMARY start={start} k={k} steps={steps} headers={} fold_s={fold_s:.2} s_per_header={:.3} \
     recursive_verify_ok={} outputs_match={accepted}",
    k * steps,
    fold_s / (k * steps) as f64,
    res.is_ok()
  );
  if compress && res.is_ok() {
    let t = Instant::now();
    let (pk, vk) = CompressedSNARK::<E1, E2, C, S1, S2>::setup(&pp).unwrap();
    let setup_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let snark = CompressedSNARK::<E1, E2, C, S1, S2>::prove(&pp, &pk, &rs).unwrap();
    let prove_s = t.elapsed().as_secs_f64();
    let proof_bytes = bincode::serialize(&snark).unwrap();
    let bytes = proof_bytes.len();
    if let Some(dir) = arg(&args, "--save") {
      let dir = std::path::PathBuf::from(dir);
      std::fs::create_dir_all(&dir).unwrap();
      std::fs::write(dir.join("proof.bin"), &proof_bytes).unwrap();
      std::fs::write(dir.join("vk.bin"), bincode::serialize(&vk).unwrap()).unwrap();
      std::fs::write(dir.join("z0.bin"), z_bytes(&z0)).unwrap();
      std::fs::write(dir.join("steps.txt"), steps.to_string()).unwrap();
      std::fs::write(dir.join("k.txt"), k.to_string()).unwrap();
      println!("saved proof, vk, z0 to {}", dir.display());
    }
    let t = Instant::now();
    let cres = snark.verify(&vk, steps as usize, &z0);
    let cverify_s = t.elapsed().as_secs_f64();
    let cok = matches!(&cres, Ok(z) if *z == state.to_z::<F1>());
    println!(
      "compressed: setup {setup_s:.2}s prove {prove_s:.2}s size {bytes} B verify {cverify_s:.3}s ok={cok} hwm_mib={}",
      hwm_mib()
    );
    summary += &format!(" compressed_prove_s={prove_s:.2} compressed_bytes={bytes} compressed_verify_ok={cok}");
  }
  println!("{summary} peak_rss_mib={}", hwm_mib());
}
