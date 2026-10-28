use super::native::*;
use super::HeaderStep;
use nova_snark::frontend::{num::AllocatedNum, test_cs::TestConstraintSystem, ConstraintSystem};
use nova_snark::provider::PallasEngine;
use nova_snark::traits::{circuit::StepCircuit, Engine};
use std::collections::BTreeMap;
use std::path::Path;

type F = <PallasEngine as Engine>::Scalar;

fn hs() -> BTreeMap<u32, Header> {
  load_headers(&Path::new(env!("CARGO_MANIFEST_DIR")).join("data"))
}

fn cp(h: u32, hs: &BTreeMap<u32, Header>) -> State {
  State::checkpoint(h, hs, early_chainwork(h))
}

struct Out {
  ok: bool,
  first_fail: String,
  constraints: usize,
  z: Vec<F>,
}

fn synth(state: &State, headers: &[Header]) -> Out {
  let mut cs = TestConstraintSystem::<F>::new();
  let z: Vec<AllocatedNum<F>> = state
    .to_z::<F>()
    .iter()
    .enumerate()
    .map(|(i, v)| AllocatedNum::alloc(cs.namespace(|| format!("z{i}")), || Ok(*v)).unwrap())
    .collect();
  let c = HeaderStep { headers: headers.to_vec() };
  let out = <HeaderStep as StepCircuit<F>>::synthesize(&c, &mut cs, &z).unwrap();
  Out {
    ok: cs.is_satisfied(),
    first_fail: cs.which_is_unsatisfied().unwrap_or("").to_string(),
    constraints: cs.num_constraints(),
    z: out.iter().map(|n| n.get_value().unwrap()).collect(),
  }
}

fn range(hs: &BTreeMap<u32, Header>, from: u32, n: u32) -> Vec<Header> {
  (from..from + n).map(|h| hs[&h]).collect()
}

fn native_after(state: &State, headers: &[Header]) -> State {
  headers.iter().fold(state.clone(), |s, h| s.apply(h).unwrap())
}

#[test]
fn ten_valid_headers_match_native_state() {
  let hs = hs();
  let s = cp(1000, &hs);
  let hdrs = range(&hs, 1001, 10);
  let o = synth(&s, &hdrs);
  assert!(o.ok, "unsatisfied at {}", o.first_fail);
  assert_eq!(o.z, native_after(&s, &hdrs).to_z::<F>());
}

#[test]
fn boundary_2016_capped_at_pow_limit() {
  let hs = hs();
  let s = cp(2010, &hs);
  let hdrs = range(&hs, 2011, 10);
  assert_eq!(next_bits(s.epoch_bits, time(&hs[&2015]), time(&hs[&0])), 0x1d00_ffff);
  let o = synth(&s, &hdrs);
  assert!(o.ok, "unsatisfied at {}", o.first_fail);
  assert_eq!(o.z, native_after(&s, &hdrs).to_z::<F>());
}

#[test]
fn first_real_retarget_32256() {
  let hs = hs();
  if !hs.contains_key(&32_256) {
    eprintln!("data/retarget.txt missing; skipped");
    return;
  }
  let s = cp(32_250, &hs);
  let hdrs = range(&hs, 32_251, 10);
  assert_eq!(bits(&hs[&32_256]), 0x1d00_d86a);
  let o = synth(&s, &hdrs);
  assert!(o.ok, "unsatisfied at {}", o.first_fail);
  assert_eq!(o.z, native_after(&s, &hdrs).to_z::<F>());

  let mut bad = hdrs.clone();
  bad[5][72..76].copy_from_slice(&0x1d00_ffffu32.to_le_bytes()); // keeps the old difficulty
  let o = synth(&s, &bad);
  assert!(!o.ok);
  assert!(o.first_fail.contains("retarget"), "{}", o.first_fail);
}

#[test]
fn wrong_bits_at_2016_rejected() {
  let hs = hs();
  let s = cp(2015, &hs);
  let mut h = hs[&2016];
  h[72..76].copy_from_slice(&0x1d00_fffeu32.to_le_bytes());
  assert_eq!(s.apply(&h), Err("retarget"));
  let o = synth(&s, &[h]);
  assert!(!o.ok && o.first_fail.contains("retarget"), "{}", o.first_fail);
}

#[test]
fn invalid_pow_rejected() {
  let hs = hs();
  let s = cp(1000, &hs);
  let mut h = hs[&1001];
  h[76] ^= 1; // nonce
  assert_eq!(s.apply(&h), Err("pow"));
  let o = synth(&s, &[h]);
  assert!(!o.ok && o.first_fail.contains("pow"), "{}", o.first_fail);
}

#[test]
fn wrong_prev_link_rejected() {
  let hs = hs();
  let mut s = cp(1000, &hs);
  s.prev[0] ^= 1;
  let o = synth(&s, &[hs[&1001]]);
  assert!(!o.ok && o.first_fail.contains("prev_link"), "{}", o.first_fail);
}

#[test]
fn mtp_violation_rejected() {
  let hs = hs();
  let s = cp(1000, &hs);
  let mut h = hs[&1001];
  h[68..72].copy_from_slice(&s.mtp().to_le_bytes());
  assert_eq!(s.apply(&h), Err("mtp"));
  let o = synth(&s, &[h]);
  assert!(!o.ok && o.first_fail.contains("mtp"), "{}", o.first_fail);
}

#[test]
fn bits_change_inside_epoch_rejected() {
  let hs = hs();
  let s = cp(1000, &hs);
  let mut h = hs[&1001];
  h[72..76].copy_from_slice(&0x1d00_fffeu32.to_le_bytes());
  assert_eq!(s.apply(&h), Err("bits_continuity"));
  let o = synth(&s, &[h]);
  assert!(!o.ok && o.first_fail.contains("bits_continuity"), "{}", o.first_fail);
}

#[test]
fn easier_than_pow_limit_rejected() {
  let hs = hs();
  let mut s = cp(1000, &hs);
  s.epoch_bits = 0x1d01_0000; // checkpoint epoch above powLimit
  let o = synth(&s, &[hs[&1001]]);
  assert!(!o.ok && o.first_fail.contains("e0_le_pl"), "{}", o.first_fail);
}

#[test]
fn version_1_after_bip34_rejected() {
  let hs = hs();
  let mut s = cp(1000, &hs);
  s.height = BIP34 - 1; // pretend the next header is at the BIP34 height
  s.chainwork = early_chainwork(1000);
  let h = hs[&1001];
  assert_eq!(version(&h), 1);
  assert_eq!(s.apply(&h), Err("version"));
  let o = synth(&s, &[h]);
  assert!(!o.ok && o.first_fail.contains("version"), "{}", o.first_fail);
}

#[test]
fn native_rules_accept_all_fixture_headers() {
  let hs = hs();
  let mut s = cp(10, &hs);
  for h in 11..=2100u32 {
    s = s.apply(&hs[&h]).unwrap_or_else(|e| panic!("height {h}: {e}"));
  }
  assert_eq!(s.chainwork, early_chainwork(2100));
}

#[test]
#[ignore]
fn constraint_counts() {
  let hs = hs();
  let s = cp(1000, &hs);
  let c1 = synth(&s, &range(&hs, 1001, 1)).constraints;
  let c10 = synth(&s, &range(&hs, 1001, 10)).constraints;
  println!("constraints k=1: {c1}  k=10: {c10}  marginal/header: {}", (c10 - c1) / 9);
}
