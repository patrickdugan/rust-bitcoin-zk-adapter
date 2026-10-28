//! Bitcoin header-chain validation as a Nova step circuit.
//!
//! Each fold step checks `k` consecutive mainnet headers against a 17-element
//! state: height, previous block hash (two 128-bit halves of its little-endian
//! integer), cumulative chainwork, the current epoch's nBits, the timestamp of
//! the epoch's first block, and the last 11 timestamps (oldest first).
//!
//! Enforced per header: previous-hash link, double SHA-256 at or below the
//! target decoded from nBits, nBits validity (no sign bit, nonzero mantissa,
//! exponent 3..=32, target <= powLimit), nBits unchanged inside an epoch, the
//! exact retarget formula at 2016-block boundaries (clamp, powLimit cap and
//! compact re-encoding), median-time-past, BIP34/66/65 version minimums and
//! work = floor(2^256 / (target + 1)) added to chainwork.
//!
//! Not enforced: the "time too far in the future" rule (needs a wall clock)
//! and best-chain selection. Targets below 2^128 and exponents below 3 are
//! rejected (never seen on mainnet).

use ff::PrimeField;
use nova_snark::frontend::{
  num::AllocatedNum, sha256, AllocatedBit, Boolean, ConstraintSystem, Index, LinearCombination,
  SynthesisError, Variable,
};
use nova_snark::traits::circuit::StepCircuit;
use num_bigint::BigUint;
use num_traits::{One, ToPrimitive, Zero};

pub mod native {
  use num_bigint::BigUint;
  use num_traits::{One, ToPrimitive};
  use sha2::{Digest, Sha256};
  use std::collections::BTreeMap;

  pub type Header = [u8; 80];
  pub const ARITY: usize = 17;
  pub const TIMESPAN: u64 = 1_209_600;
  pub const INTERVAL: u32 = 2016;
  pub const BIP34: u32 = 227_931;
  pub const BIP66: u32 = 363_725;
  pub const BIP65: u32 = 388_381;

  pub fn pow_limit() -> BigUint {
    (BigUint::one() << 224u32) - BigUint::one()
  }
  fn u32_at(h: &Header, o: usize) -> u32 {
    u32::from_le_bytes(h[o..o + 4].try_into().unwrap())
  }
  pub fn version(h: &Header) -> u32 {
    u32_at(h, 0)
  }
  pub fn time(h: &Header) -> u32 {
    u32_at(h, 68)
  }
  pub fn bits(h: &Header) -> u32 {
    u32_at(h, 72)
  }
  pub fn prev(h: &Header) -> [u8; 32] {
    h[4..36].try_into().unwrap()
  }
  /// Double SHA-256 in internal byte order (the little-endian integer).
  pub fn hash(h: &Header) -> [u8; 32] {
    let a = Sha256::digest(h);
    Sha256::digest(a).into()
  }
  /// Core's SetCompact, restricted to what the circuit accepts.
  pub fn decode_compact(bits: u32) -> Option<BigUint> {
    let e = bits >> 24;
    let m = bits & 0x007f_ffff;
    if bits & 0x0080_0000 != 0 || m == 0 || !(3..=32).contains(&e) {
      return None;
    }
    Some(BigUint::from(m) << (8 * (e - 3)))
  }
  /// Core's GetCompact.
  pub fn get_compact(v: &BigUint) -> u32 {
    let mut size = v.bits().div_ceil(8) as u32;
    let mut c: u32 = if size <= 3 {
      (v.to_u64().unwrap() << (8 * (3 - size))) as u32
    } else {
      (v >> (8 * (size - 3))).to_u32().unwrap()
    };
    if c & 0x0080_0000 != 0 {
      c >>= 8;
      size += 1;
    }
    c | (size << 24)
  }
  pub fn work(target: &BigUint) -> BigUint {
    (BigUint::one() << 256u32) / (target + 1u32)
  }
  /// Core's CalculateNextWorkRequired for mainnet.
  pub fn next_bits(epoch_bits: u32, ts_prev: u32, epoch_start: u32) -> u32 {
    let t = TIMESPAN as i64;
    let span = (ts_prev as i64 - epoch_start as i64).clamp(t / 4, t * 4);
    let mut n = decode_compact(epoch_bits).expect("valid epoch bits") * BigUint::from(span as u64)
      / BigUint::from(TIMESPAN);
    if n > pow_limit() {
      n = pow_limit();
    }
    get_compact(&n)
  }

  /// Headers from `data/headers_0_2100.bin` (raw, from height 0) and
  /// `data/retarget.txt` ("height hex" lines), each checked against its height chain.
  pub fn load_headers(dir: &std::path::Path) -> BTreeMap<u32, Header> {
    let mut hs = BTreeMap::new();
    let raw = std::fs::read(dir.join("headers_0_2100.bin")).expect("headers_0_2100.bin");
    for (i, c) in raw.chunks(80).enumerate() {
      hs.insert(i as u32, c.try_into().unwrap());
    }
    if let Ok(txt) = std::fs::read_to_string(dir.join("retarget.txt")) {
      for line in txt.lines().filter(|l| !l.trim().is_empty()) {
        let mut it = line.split_whitespace();
        let h: u32 = it.next().unwrap().parse().unwrap();
        let bytes = hex::decode(it.next().unwrap()).unwrap();
        hs.insert(h, bytes.try_into().unwrap());
      }
    }
    for (h, hdr) in hs.iter() {
      if let Some(next) = hs.get(&(h + 1)) {
        assert_eq!(prev(next), hash(hdr), "header {} does not link to {}", h + 1, h);
      }
    }
    hs
  }

  /// Chainwork through `height` while every block had nBits 0x1d00ffff (< 32256).
  pub fn early_chainwork(height: u32) -> BigUint {
    assert!(height < 32_256, "difficulty first changed at 32256");
    work(&decode_compact(0x1d00_ffff).unwrap()) * BigUint::from(height + 1)
  }

  #[derive(Clone, Debug, PartialEq)]
  pub struct State {
    pub height: u32,
    pub prev: [u8; 32],
    pub chainwork: BigUint,
    pub epoch_bits: u32,
    pub epoch_start: u32,
    pub ts: [u32; 11],
  }

  impl State {
    /// Authenticated checkpoint at `height` (its header is the last one validated).
    pub fn checkpoint(height: u32, hs: &BTreeMap<u32, Header>, chainwork: BigUint) -> State {
      assert!(height >= 10, "checkpoint needs 11 timestamps");
      let mut ts = [0u32; 11];
      for (i, t) in ts.iter_mut().enumerate() {
        *t = time(&hs[&(height - 10 + i as u32)]);
      }
      State {
        height,
        prev: hash(&hs[&height]),
        chainwork,
        epoch_bits: bits(&hs[&height]),
        epoch_start: time(&hs[&(height - height % INTERVAL)]),
        ts,
      }
    }
    pub fn mtp(&self) -> u32 {
      let mut s = self.ts;
      s.sort_unstable();
      s[5]
    }
    /// Native mirror of the circuit; the error names the failing check.
    pub fn apply(&self, h: &Header) -> Result<State, &'static str> {
      let height = self.height + 1;
      if prev(h) != self.prev {
        return Err("prev_link");
      }
      let req = 1 + (height >= BIP34) as i32 + (height >= BIP66) as i32 + (height >= BIP65) as i32;
      if height >= BIP34 && (version(h) as i32) < req {
        return Err("version");
      }
      let t = time(h);
      if t <= self.mtp() {
        return Err("mtp");
      }
      let b = bits(h);
      let target = decode_compact(b).ok_or("nbits")?;
      if target > pow_limit() {
        return Err("target_le_powlimit");
      }
      if height % INTERVAL != 0 {
        if b != self.epoch_bits {
          return Err("bits_continuity");
        }
      } else if b != next_bits(self.epoch_bits, self.ts[10], self.epoch_start) {
        return Err("retarget");
      }
      let w = work(&target);
      if w.bits() > 128 {
        return Err("work_range");
      }
      if BigUint::from_bytes_le(&hash(h)) > target {
        return Err("pow");
      }
      let mut ts = [0u32; 11];
      ts[..10].copy_from_slice(&self.ts[1..]);
      ts[10] = t;
      Ok(State {
        height,
        prev: hash(h),
        chainwork: &self.chainwork + w,
        epoch_bits: b,
        epoch_start: if height % INTERVAL == 0 { t } else { self.epoch_start },
        ts,
      })
    }
    pub fn to_z<F: ff::PrimeField>(&self) -> Vec<F> {
      let big = |b: &BigUint| F::from_str_vartime(&b.to_str_radix(10)).unwrap();
      let mut z = vec![
        F::from(self.height as u64),
        big(&BigUint::from_bytes_le(&self.prev[..16])),
        big(&BigUint::from_bytes_le(&self.prev[16..])),
        big(&self.chainwork),
        F::from(self.epoch_bits as u64),
        F::from(self.epoch_start as u64),
      ];
      z.extend(self.ts.iter().map(|&t| F::from(t as u64)));
      z
    }
  }
}

use native::{Header, ARITY, BIP34, BIP65, BIP66, INTERVAL, TIMESPAN};

type Val = Option<BigUint>;

/// A linear combination together with its native integer value.
#[derive(Clone)]
struct Lv<F: PrimeField> {
  lc: LinearCombination<F>,
  v: Val,
}

fn one() -> Variable {
  Variable::new_unchecked(Index::Input(0))
}
fn f_of<F: PrimeField>(b: &BigUint) -> F {
  F::from_str_vartime(&b.to_str_radix(10)).expect("value fits the field")
}
fn big_of<F: PrimeField>(f: &F) -> BigUint {
  BigUint::from_bytes_le(f.to_repr().as_ref())
}
fn opt2<A, B, R>(a: &Option<A>, b: &Option<B>, f: impl Fn(&A, &B) -> R) -> Option<R> {
  match (a, b) {
    (Some(x), Some(y)) => Some(f(x, y)),
    _ => None,
  }
}

impl<F: PrimeField> Lv<F> {
  fn konst(c: u64) -> Self {
    Lv { lc: LinearCombination::zero() + (F::from(c), one()), v: Some(BigUint::from(c)) }
  }
  fn konst_big(c: &BigUint) -> Self {
    Lv { lc: LinearCombination::zero() + (f_of::<F>(c), one()), v: Some(c.clone()) }
  }
  fn num(n: &AllocatedNum<F>) -> Self {
    Lv { lc: LinearCombination::zero() + n.get_variable(), v: n.get_value().map(|f| big_of(&f)) }
  }
  fn add(&self, o: &Lv<F>) -> Self {
    Lv { lc: self.lc.clone() + &o.lc, v: opt2(&self.v, &o.v, |a, b| a + b) }
  }
  fn fval(&self) -> Option<F> {
    self.v.as_ref().map(f_of)
  }
}

fn bits_val(bits: &[Boolean]) -> Val {
  let mut v = BigUint::zero();
  for (i, b) in bits.iter().enumerate() {
    if b.get_value()? {
      v += BigUint::one() << i;
    }
  }
  Some(v)
}

/// Little-endian packing (at most 200 bits, so it is injective in the field).
fn pack<F: PrimeField>(bits: &[Boolean]) -> Lv<F> {
  Lv { lc: pack_scaled(bits, F::ONE), v: bits_val(bits) }
}

/// c0 * (little-endian packing of bits).
fn pack_scaled<F: PrimeField>(bits: &[Boolean], c0: F) -> LinearCombination<F> {
  assert!(bits.len() <= 200);
  let mut lc = LinearCombination::zero();
  let mut c = c0;
  for b in bits {
    lc = lc + &b.lc(one(), c);
    c = c.double();
  }
  lc
}

fn const_bits(v: &BigUint, n: usize) -> Vec<Boolean> {
  (0..n).map(|i| Boolean::constant(v.bit(i as u64))).collect()
}

fn alloc_bits<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  v: &Val,
  n: usize,
) -> Result<Vec<Boolean>, SynthesisError> {
  (0..n)
    .map(|i| {
      AllocatedBit::alloc(cs.namespace(|| format!("b{i}")), v.as_ref().map(|x| x.bit(i as u64)))
        .map(Boolean::from)
    })
    .collect()
}

fn enforce_eq<F: PrimeField, CS: ConstraintSystem<F>>(cs: &mut CS, name: &str, a: &Lv<F>, b: &Lv<F>) {
  cs.enforce(|| name.to_string(), |lc| lc + &a.lc - &b.lc, |lc| lc + one(), |lc| lc);
}
fn enforce_true<F: PrimeField, CS: ConstraintSystem<F>>(cs: &mut CS, name: &str, b: &Boolean) {
  cs.enforce(|| name.to_string(), |lc| lc + one() - &b.lc(one(), F::ONE), |lc| lc + one(), |lc| lc);
}
/// (a - b) * cond = 0
fn enforce_eq_if<F: PrimeField, CS: ConstraintSystem<F>>(
  cs: &mut CS,
  name: &str,
  cond: &LinearCombination<F>,
  a: &Lv<F>,
  b: &Lv<F>,
) {
  cs.enforce(|| name.to_string(), |lc| lc + &a.lc - &b.lc, |lc| lc + cond, |lc| lc);
}

/// Range-check `x` to n bits and return its bits.
fn decompose<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  x: &Lv<F>,
  n: usize,
) -> Result<Vec<Boolean>, SynthesisError> {
  let bits = alloc_bits(cs.namespace(|| "bits"), &x.v, n)?;
  let p = pack::<F>(&bits);
  enforce_eq(&mut cs, "pack", &p, x);
  Ok(bits)
}

/// a >= b for 0 <= a < 2^n and 0 <= b <= 2^n.
fn ge<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  a: &Lv<F>,
  b: &Lv<F>,
  n: usize,
) -> Result<Boolean, SynthesisError> {
  let off = BigUint::one() << n;
  let d = Lv {
    lc: a.lc.clone() - &b.lc + (f_of::<F>(&off), one()),
    v: opt2(&a.v, &b.v, |x, y| {
      let s = x + &off;
      if &s >= y { s - y } else { BigUint::zero() }
    }),
  };
  Ok(decompose(cs.namespace(|| "d"), &d, n + 1)?[n].clone())
}

fn is_zero<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  x: &LinearCombination<F>,
  xv: Option<F>,
) -> Result<Boolean, SynthesisError> {
  let inv = AllocatedNum::alloc(cs.namespace(|| "inv"), || {
    let f = xv.ok_or(SynthesisError::AssignmentMissing)?;
    Ok(Option::<F>::from(f.invert()).unwrap_or(F::ZERO))
  })?;
  let out = AllocatedBit::alloc(cs.namespace(|| "out"), xv.map(|f| bool::from(f.is_zero())))?;
  cs.enforce(|| "x*inv=1-out", |lc| lc + x, |lc| lc + inv.get_variable(), |lc| lc + one() - out.get_variable());
  cs.enforce(|| "x*out=0", |lc| lc + x, |lc| lc + out.get_variable(), |lc| lc);
  Ok(Boolean::from(out))
}

/// a <= b for 256-bit little-endian bit vectors.
fn le256<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  a: &[Boolean],
  b: &[Boolean],
) -> Result<Boolean, SynthesisError> {
  let (alo, ahi) = (pack::<F>(&a[..128]), pack::<F>(&a[128..]));
  let (blo, bhi) = (pack::<F>(&b[..128]), pack::<F>(&b[128..]));
  let lo_le = ge(cs.namespace(|| "lo"), &blo, &alo, 128)?;
  let hi_ge = ge(cs.namespace(|| "hi"), &ahi, &bhi, 128)?;
  let diff = bhi.lc.clone() - &ahi.lc;
  let eq_hi = is_zero(cs.namespace(|| "eq_hi"), &diff, opt2(&bhi.fval(), &ahi.fval(), |x, y| *x - *y))?;
  let lo_case = Boolean::and(cs.namespace(|| "eq_and_lo"), &eq_hi, &lo_le)?;
  Boolean::or(cs.namespace(|| "res"), &hi_ge.not(), &lo_case)
}

/// Bitwise cond ? a : b (result is boolean because cond is).
fn select_bits<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  cond: &Boolean,
  a: &[Boolean],
  b: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError> {
  let mut out = Vec::with_capacity(a.len());
  for (i, (x, y)) in a.iter().zip(b).enumerate() {
    let val = match (cond.get_value(), x.get_value(), y.get_value()) {
      (Some(c), Some(x), Some(y)) => Some(if c { x } else { y }),
      _ => None,
    };
    let var = cs.alloc(
      || format!("r{i}"),
      || val.map(|v| if v { F::ONE } else { F::ZERO }).ok_or(SynthesisError::AssignmentMissing),
    )?;
    cs.enforce(
      || format!("sel{i}"),
      |lc| lc + &cond.lc(one(), F::ONE),
      |lc| lc + &x.lc(one(), F::ONE) - &y.lc(one(), F::ONE),
      |lc| lc + var - &y.lc(one(), F::ONE),
    );
    out.push(Boolean::Is(AllocatedBit::from_parts_unchecked(var, val)));
  }
  Ok(out)
}

fn limbs<F: PrimeField>(bits: &[Boolean]) -> Vec<Lv<F>> {
  bits.chunks(64).map(pack::<F>).collect()
}

/// a * b + add over 64-bit limbs, returned as range-checked normalized limbs
/// (one per column plus a final carry limb).
fn mul_add<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  a: &[Lv<F>],
  b: &[Lv<F>],
  add: &[Lv<F>],
) -> Result<Vec<Lv<F>>, SynthesisError> {
  let ncols = (a.len() + b.len() - 1).max(add.len());
  let mut cols: Vec<Lv<F>> = (0..ncols).map(|_| Lv::konst(0)).collect();
  for (i, ai) in a.iter().enumerate() {
    for (j, bj) in b.iter().enumerate() {
      let pv = opt2(&ai.v, &bj.v, |x, y| x * y);
      let p = AllocatedNum::alloc(cs.namespace(|| format!("p{i}_{j}")), || {
        pv.as_ref().map(f_of).ok_or(SynthesisError::AssignmentMissing)
      })?;
      cs.enforce(|| format!("mul{i}_{j}"), |lc| lc + &ai.lc, |lc| lc + &bj.lc, |lc| lc + p.get_variable());
      cols[i + j] = cols[i + j].add(&Lv { lc: LinearCombination::zero() + p.get_variable(), v: pv });
    }
  }
  for (k, x) in add.iter().enumerate() {
    cols[k] = cols[k].add(x);
  }
  let mask = (BigUint::one() << 64u32) - BigUint::one();
  let two64 = f_of::<F>(&(BigUint::one() << 64u32));
  let mut carry = Lv::konst(0);
  let mut out = Vec::with_capacity(ncols + 1);
  for (k, col) in cols.iter().enumerate() {
    let s = col.add(&carry);
    let lo_bits = alloc_bits(cs.namespace(|| format!("lo{k}")), &s.v.as_ref().map(|v| v & &mask), 64)?;
    let hi_bits = alloc_bits(cs.namespace(|| format!("c{k}")), &s.v.as_ref().map(|v| v >> 64u32), 72)?;
    let (lo, hi) = (pack::<F>(&lo_bits), pack::<F>(&hi_bits));
    let hi_scaled = pack_scaled(&hi_bits, two64);
    cs.enforce(
      || format!("col{k}"),
      |lc| lc + &s.lc - &lo.lc - &hi_scaled,
      |lc| lc + one(),
      |lc| lc,
    );
    out.push(lo);
    carry = hi;
  }
  out.push(carry);
  Ok(out)
}

struct Decoded {
  target: Vec<Boolean>,
  sel: Vec<Boolean>,
  mant: Vec<Boolean>,
}

/// nBits (32 LE bits) -> 256 target bits; enforces exponent 3..=32, no sign
/// bit and a nonzero mantissa.
fn decode<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  nbits: &[Boolean],
) -> Result<Decoded, SynthesisError> {
  let mant = nbits[..23].to_vec();
  enforce_eq(&mut cs, "no_sign", &pack::<F>(&nbits[23..24]), &Lv::konst(0));
  let exp = pack::<F>(&nbits[24..32]);
  let ev = exp.v.as_ref().and_then(|v| v.to_u32());
  let sel: Vec<Boolean> = (3u32..=32)
    .map(|e| AllocatedBit::alloc(cs.namespace(|| format!("sel{e}")), ev.map(|x| x == e)).map(Boolean::from))
    .collect::<Result<_, _>>()?;
  let mut sum = LinearCombination::zero();
  let mut wsum = LinearCombination::zero();
  for (i, s) in sel.iter().enumerate() {
    sum = sum + &s.lc(one(), F::ONE);
    wsum = wsum + &s.lc(one(), F::from(i as u64 + 3));
  }
  cs.enforce(|| "one_hot", |lc| lc + &sum - one(), |lc| lc + one(), |lc| lc);
  cs.enforce(|| "exp", |lc| lc + &wsum - &exp.lc, |lc| lc + one(), |lc| lc);
  let mut terms: Vec<Option<(LinearCombination<F>, Option<bool>)>> = vec![None; 256];
  for (idx, s) in sel.iter().enumerate() {
    for (j, m) in mant.iter().enumerate() {
      let pos = 8 * idx + j;
      if pos >= 256 {
        continue;
      }
      let p = Boolean::and(cs.namespace(|| format!("p{idx}_{j}")), s, m)?;
      let entry = terms[pos].get_or_insert((LinearCombination::zero(), Some(false)));
      entry.0 = entry.0.clone() + &p.lc(one(), F::ONE);
      entry.1 = opt2(&entry.1, &p.get_value(), |a, b| *a || *b);
    }
  }
  let mut target = Vec::with_capacity(256);
  for (i, t) in terms.into_iter().enumerate() {
    match t {
      None => target.push(Boolean::constant(false)),
      Some((lc_t, val)) => {
        let var = cs.alloc(
          || format!("t{i}"),
          || val.map(|v| if v { F::ONE } else { F::ZERO }).ok_or(SynthesisError::AssignmentMissing),
        )?;
        cs.enforce(|| format!("t{i}_eq"), |lc| lc + &lc_t - var, |lc| lc + one(), |lc| lc);
        target.push(Boolean::Is(AllocatedBit::from_parts_unchecked(var, val)));
      }
    }
  }
  let m = pack::<F>(&mant);
  let mz = is_zero(cs.namespace(|| "mant_zero"), &m.lc, m.fval())?;
  enforce_eq(&mut cs, "mant_nonzero", &pack::<F>(&[mz]), &Lv::konst(0));
  Ok(Decoded { target, sel, mant })
}

fn pow_limit_bits() -> Vec<Boolean> {
  const_bits(&native::pow_limit(), 256)
}

/// Header at a boundary must carry compact(min(powLimit, old * clamp(span) / T)).
#[allow(clippy::too_many_arguments)]
fn retarget<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  t_old: &[Boolean],
  ts_prev: &Lv<F>,
  estart: &Lv<F>,
  d: &Decoded,
  is_b: &Boolean,
) -> Result<(), SynthesisError> {
  let two32 = BigUint::one() << 32u32;
  let (lo_c, hi_c) = (TIMESPAN / 4, TIMESPAN * 4);
  let x = Lv {
    lc: ts_prev.lc.clone() - &estart.lc + (f_of::<F>(&two32), one()),
    v: opt2(&ts_prev.v, &estart.v, |a, b| a + &two32 - b),
  };
  decompose(cs.namespace(|| "x"), &x, 33)?;
  let ge_l = ge(cs.namespace(|| "ge_l"), &x, &Lv::konst_big(&(&two32 + lo_c)), 33)?;
  let gt_h = ge(cs.namespace(|| "gt_h"), &x, &Lv::konst_big(&(&two32 + hi_c + 1u32)), 33)?;
  let span_i64 = opt2(&ts_prev.v, &estart.v, |a, b| a.to_i64().unwrap() - b.to_i64().unwrap());
  let tmp_v = span_i64.map(|s| if s >= lo_c as i64 { s as u64 } else { lo_c });
  let tmp = AllocatedNum::alloc(cs.namespace(|| "tmp"), || tmp_v.map(F::from).ok_or(SynthesisError::AssignmentMissing))?;
  cs.enforce(
    || "tmp_sel",
    |lc| lc + &ge_l.lc(one(), F::ONE),
    |lc| lc + &x.lc - (f_of::<F>(&(&two32 + lo_c)), one()),
    |lc| lc + tmp.get_variable() - (F::from(lo_c), one()),
  );
  let span_v = tmp_v.map(|t| t.min(hi_c));
  let span = AllocatedNum::alloc(cs.namespace(|| "span"), || span_v.map(F::from).ok_or(SynthesisError::AssignmentMissing))?;
  cs.enforce(
    || "span_sel",
    |lc| lc + &gt_h.lc(one(), F::ONE),
    |lc| lc + (F::from(hi_c), one()) - tmp.get_variable(),
    |lc| lc + span.get_variable() - tmp.get_variable(),
  );
  let span_lv = Lv { lc: LinearCombination::zero() + span.get_variable(), v: span_v.map(BigUint::from) };
  let xo = mul_add(cs.namespace(|| "x_mul"), &limbs::<F>(t_old), &[span_lv.clone()], &[])?;
  let prod = opt2(&bits_val(t_old), &span_lv.v, |t, s| t * s);
  let q_v = prod.as_ref().map(|p| p / TIMESPAN);
  let r_v = prod.as_ref().map(|p| p % TIMESPAN);
  let qb = alloc_bits(cs.namespace(|| "q"), &q_v, 256)?;
  let rb = alloc_bits(cs.namespace(|| "r"), &r_v, 21)?;
  let r = pack::<F>(&rb);
  let r_room = Lv {
    lc: LinearCombination::zero() + (F::from(TIMESPAN - 1), one()) - &r.lc,
    v: r.v.as_ref().map(|v| BigUint::from(TIMESPAN - 1) - v.min(&BigUint::from(TIMESPAN - 1))),
  };
  decompose(cs.namespace(|| "r_lt"), &r_room, 21)?;
  let yo = mul_add(cs.namespace(|| "y_mul"), &limbs::<F>(&qb), &[Lv::konst(TIMESPAN)], &[r])?;
  for (k, (a, b)) in xo.iter().zip(&yo).enumerate() {
    enforce_eq(&mut cs, &format!("divmod{k}"), a, b);
  }
  let q_le = le256(cs.namespace(|| "q_le_pl"), &qb, &pow_limit_bits())?;
  let new_t = select_bits(cs.namespace(|| "new_t"), &q_le, &qb, &pow_limit_bits())?;
  // Clear the bits below the header's exponent shift; the rest must equal its target.
  let mut trunc = Vec::with_capacity(256);
  for (i, nt) in new_t.iter().enumerate() {
    let mut p = LinearCombination::zero();
    let mut pv = Some(false);
    for (idx, s) in d.sel.iter().enumerate() {
      if 8 * idx <= i {
        p = p + &s.lc(one(), F::ONE);
        pv = opt2(&pv, &s.get_value(), |a, b| *a || *b);
      }
    }
    let val = opt2(&nt.get_value(), &pv, |a, b| *a && *b);
    let var = cs.alloc(
      || format!("tr{i}"),
      || val.map(|v| if v { F::ONE } else { F::ZERO }).ok_or(SynthesisError::AssignmentMissing),
    )?;
    cs.enforce(|| format!("trunc{i}"), |lc| lc + &nt.lc(one(), F::ONE), |lc| lc + &p, |lc| lc + var);
    trunc.push(Boolean::Is(AllocatedBit::from_parts_unchecked(var, val)));
  }
  let cond = is_b.lc(one(), F::ONE);
  enforce_eq_if(&mut cs, "retarget_lo", &cond, &pack::<F>(&trunc[..128]), &pack::<F>(&d.target[..128]));
  enforce_eq_if(&mut cs, "retarget_hi", &cond, &pack::<F>(&trunc[128..]), &pack::<F>(&d.target[128..]));
  let hi8 = pack::<F>(&d.mant[15..23]);
  let z = is_zero(cs.namespace(|| "mant_hi_zero"), &hi8.lc, hi8.fval())?;
  enforce_eq_if(&mut cs, "retarget_normalized", &cond, &pack::<F>(&[z]), &Lv::konst(0));
  Ok(())
}

/// floor(2^256 / (T + 1)), proven as w*(T+1) + R = 2^256 with R <= T.
fn work<F: PrimeField, CS: ConstraintSystem<F>>(mut cs: CS, t: &[Boolean]) -> Result<Lv<F>, SynthesisError> {
  let two256 = BigUint::one() << 256u32;
  let tv = bits_val(t);
  let w_v = tv.as_ref().map(|t| &two256 / (t + 1u32));
  let r_v = opt2(&tv, &w_v, |t, w| &two256 - w * (t + 1u32));
  let wb = alloc_bits(cs.namespace(|| "w"), &w_v, 128)?;
  let rb = alloc_bits(cs.namespace(|| "r"), &r_v, 256)?;
  let (wl, rl) = (limbs::<F>(&wb), limbs::<F>(&rb));
  let add: Vec<Lv<F>> = (0..4).map(|k| if k < 2 { rl[k].add(&wl[k]) } else { rl[k].clone() }).collect();
  let out = mul_add(cs.namespace(|| "mul"), &wl, &limbs::<F>(t), &add)?;
  for (k, limb) in out.iter().enumerate() {
    enforce_eq(&mut cs, &format!("limb{k}"), limb, &Lv::konst((k == 4) as u64));
  }
  let r_le = le256(cs.namespace(|| "r_le_t"), &rb, t)?;
  enforce_true(&mut cs, "r_le_t_ok", &r_le);
  Ok(pack::<F>(&wb))
}

fn alloc_lv<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  x: &Lv<F>,
) -> Result<AllocatedNum<F>, SynthesisError> {
  let n = AllocatedNum::alloc(cs.namespace(|| "n"), || x.fval().ok_or(SynthesisError::AssignmentMissing))?;
  cs.enforce(|| "eq", |lc| lc + &x.lc - n.get_variable(), |lc| lc + one(), |lc| lc);
  Ok(n)
}

/// `k` consecutive headers per fold step.
#[derive(Clone, Debug)]
pub struct HeaderStep {
  pub headers: Vec<Header>,
}

impl<F: PrimeField> StepCircuit<F> for HeaderStep {
  fn arity(&self) -> usize {
    ARITY
  }

  fn synthesize<CS: ConstraintSystem<F>>(
    &self,
    cs: &mut CS,
    z: &[AllocatedNum<F>],
  ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    let mut height = Lv::num(&z[0]);
    let mut prev_lo = Lv::num(&z[1]);
    let mut prev_hi = Lv::num(&z[2]);
    let mut cw = Lv::num(&z[3]);
    let mut ebits = decompose(cs.namespace(|| "ebits0"), &Lv::num(&z[4]), 32)?;
    let mut etarget = decode(cs.namespace(|| "edecode0"), &ebits)?.target;
    let ok = le256(cs.namespace(|| "e0_le_pl"), &etarget, &pow_limit_bits())?;
    enforce_true(cs, "e0_le_pl_ok", &ok);
    let mut estart = Lv::num(&z[5]);
    let mut ts: Vec<Lv<F>> = (6..17).map(|i| Lv::num(&z[i])).collect();

    for (j, hdr) in self.headers.iter().enumerate() {
      let mut cs = cs.namespace(|| format!("h{j}"));
      let hb: Vec<Boolean> = (0..640)
        .map(|i| {
          AllocatedBit::alloc(cs.namespace(|| format!("hb{i}")), Some((hdr[i / 8] >> (7 - i % 8)) & 1 == 1))
            .map(Boolean::from)
        })
        .collect::<Result<_, _>>()?;
      let field = |off: usize, n: usize| -> Vec<Boolean> {
        (0..8 * n).map(|i| hb[8 * (off + i / 8) + 7 - i % 8].clone()).collect()
      };
      let (ver, prevb, timeb, nb) = (field(0, 4), field(4, 32), field(68, 4), field(72, 4));

      enforce_eq(&mut cs, "prev_link_lo", &pack::<F>(&prevb[..128]), &prev_lo);
      enforce_eq(&mut cs, "prev_link_hi", &pack::<F>(&prevb[128..]), &prev_hi);

      let h_new = height.add(&Lv::konst(1));
      let qb = alloc_bits(cs.namespace(|| "hq"), &h_new.v.as_ref().map(|h| h / INTERVAL), 22)?;
      let rb = alloc_bits(cs.namespace(|| "hr"), &h_new.v.as_ref().map(|h| h % INTERVAL), 11)?;
      let r = pack::<F>(&rb);
      let q_scaled = pack_scaled(&qb, F::from(INTERVAL as u64));
      cs.enforce(
        || "height_divmod",
        |lc| lc + &q_scaled + &r.lc - &h_new.lc,
        |lc| lc + one(),
        |lc| lc,
      );
      let room = Lv {
        lc: LinearCombination::zero() + (F::from(INTERVAL as u64 - 1), one()) - &r.lc,
        v: r.v.as_ref().map(|v| BigUint::from(INTERVAL - 1) - v.min(&BigUint::from(INTERVAL - 1))),
      };
      decompose(cs.namespace(|| "hr_lt"), &room, 11)?;
      let is_b = is_zero(cs.namespace(|| "is_boundary"), &r.lc, r.fval())?;

      // Version minimums (BIP34/66/65), with Core's signed comparison.
      let b1 = ge(cs.namespace(|| "bip34"), &h_new, &Lv::konst(BIP34 as u64), 33)?;
      let b2 = ge(cs.namespace(|| "bip66"), &h_new, &Lv::konst(BIP66 as u64), 33)?;
      let b3 = ge(cs.namespace(|| "bip65"), &h_new, &Lv::konst(BIP65 as u64), 33)?;
      let req = Lv {
        lc: LinearCombination::zero() + one() + &b1.lc(one(), F::ONE) + &b2.lc(one(), F::ONE) + &b3.lc(one(), F::ONE),
        v: match (b1.get_value(), b2.get_value(), b3.get_value()) {
          (Some(a), Some(b), Some(c)) => Some(BigUint::from(1u32 + a as u32 + b as u32 + c as u32)),
          _ => None,
        },
      };
      let ver_ge = ge(cs.namespace(|| "version_ge"), &pack::<F>(&ver[..31]), &req, 31)?;
      let nonneg_ge = Boolean::and(cs.namespace(|| "version_nn"), &ver[31].not(), &ver_ge)?;
      let ver_ok = Boolean::or(cs.namespace(|| "version_or"), &b1.not(), &nonneg_ge)?;
      enforce_true(&mut cs, "version_ok", &ver_ok);

      // Median-time-past: at least 6 of the previous 11 timestamps are < t.
      let t = pack::<F>(&timeb);
      let mut cnt = Lv::konst(0);
      for (i, s) in ts.iter().enumerate() {
        let lt = ge(cs.namespace(|| format!("mtp{i}")), &t, &s.add(&Lv::konst(1)), 32)?;
        cnt = cnt.add(&pack::<F>(&[lt]));
      }
      let excess = Lv {
        lc: cnt.lc.clone() - (F::from(6u64), one()),
        v: cnt.v.as_ref().map(|c| if c >= &BigUint::from(6u32) { c - 6u32 } else { BigUint::from(8u32) }),
      };
      decompose(cs.namespace(|| "mtp_count"), &excess, 3)?;

      let d = decode(cs.namespace(|| "nbits"), &nb)?;
      let pl = le256(cs.namespace(|| "target_le_powlimit"), &d.target, &pow_limit_bits())?;
      enforce_true(&mut cs, "target_le_powlimit_ok", &pl);
      let not_b = LinearCombination::zero() + one() - &is_b.lc(one(), F::ONE);
      enforce_eq_if(&mut cs, "bits_continuity", &not_b, &pack::<F>(&nb), &pack::<F>(&ebits));
      retarget(cs.namespace(|| "retarget"), &etarget, &ts[10], &estart, &d, &is_b)?;
      let w = work(cs.namespace(|| "work"), &d.target)?;

      let h1 = sha256(cs.namespace(|| "sha1"), &hb)?;
      let h2 = sha256(cs.namespace(|| "sha2"), &h1)?;
      let hash_le: Vec<Boolean> = (0..256).map(|i| h2[8 * (i / 8) + 7 - i % 8].clone()).collect();
      let pow = le256(cs.namespace(|| "pow"), &hash_le, &d.target)?;
      enforce_true(&mut cs, "pow_ok", &pow);

      // State update.
      height = h_new;
      prev_lo = pack::<F>(&hash_le[..128]);
      prev_hi = pack::<F>(&hash_le[128..]);
      cw = Lv::num(&alloc_lv(cs.namespace(|| "cw"), &cw.add(&w))?);
      let es_v = match is_b.get_value() {
        Some(true) => t.v.clone(),
        Some(false) => estart.v.clone(),
        None => None,
      };
      let es = AllocatedNum::alloc(cs.namespace(|| "estart"), || {
        es_v.as_ref().map(f_of).ok_or(SynthesisError::AssignmentMissing)
      })?;
      cs.enforce(
        || "estart_sel",
        |lc| lc + &is_b.lc(one(), F::ONE),
        |lc| lc + &t.lc - &estart.lc,
        |lc| lc + es.get_variable() - &estart.lc,
      );
      estart = Lv::num(&es);
      ebits = nb;
      etarget = d.target;
      ts.remove(0);
      ts.push(t);
    }

    let mut outs = vec![height, prev_lo, prev_hi, cw, pack::<F>(&ebits), estart];
    outs.extend(ts);
    outs
      .iter()
      .enumerate()
      .map(|(i, x)| alloc_lv(cs.namespace(|| format!("out{i}")), x))
      .collect()
  }
}

#[cfg(test)]
mod tests;
