#!/bin/sh
# For CPUs without ADX (e.g. Haswell VPS vCPUs): nova-snark enables
# halo2curves' "asm" feature on x86_64, whose code uses ADX and dies with
# SIGILL. Vendor nova-snark 0.76.0 without it and patch it in.
set -eu
cd "$(dirname "$0")/.."
cargo fetch -q
N=$(ls -d "${CARGO_HOME:-$HOME/.cargo}"/registry/src/*/nova-snark-0.76.0 | head -1)
rm -rf vendor/nova-snark && mkdir -p vendor && cp -r "$N" vendor/nova-snark
python3 - <<'PY'
p = "vendor/nova-snark/Cargo.toml"
s = open(p).read()
i = s.index("[target.'cfg(target_arch = \"x86_64\")'.dependencies.halo2curves]")
j = s.index("]", s.index("features = [", i))
s = s[:i] + s[i:j].replace('"asm",', "") + s[j:]
open(p, "w").write(s)
PY
grep -q '^\[patch.crates-io\]' Cargo.toml || printf '\n[patch.crates-io]\nnova-snark = { path = "vendor/nova-snark" }\n' >> Cargo.toml
echo "vendored nova-snark without halo2curves/asm"
