# TradeLayer strict/legacy differential replay

As of 2026-10-22 this is an **experimental parser-compatibility harness**.
The included 12 replay cases are synthetic. They establish deterministic
software behavior, rather than any Litecoin, Bitcoin, or Dogecoin historical
consensus decision. See the independently authenticated Bitcoin fixtures in
the existing Bitcoin vector tests.

## Pinned reference source

TradeLayer.js default branch, inspected commit:
[dca0888b827c5bc28fa9189bc9e1d507f5c5670c](https://github.com/patrickdugan/tradelayer.js/tree/dca0888b827c5bc28fa9189bc9e1d507f5c5670c).

- The [historical indexer](https://github.com/patrickdugan/tradelayer.js/blob/dca0888b827c5bc28fa9189bc9e1d507f5c5670c/src/txIndex.js) searches serialized script hex for the ASCII hex marker 746c, accepts a match within the first seven hex nibbles, applies offset-specific substring logic, and restricts the decoded remainder to printable ASCII.
- The [outer encoder](https://github.com/patrickdugan/tradelayer.js/blob/dca0888b827c5bc28fa9189bc9e1d507f5c5670c/src/types.js) prepends the marker and type byte; selected helpers in [txEncoder.js](https://github.com/patrickdugan/tradelayer.js/blob/dca0888b827c5bc28fa9189bc9e1d507f5c5670c/src/txEncoder.js) prepend their own marker and type as well. This produces a plausible duplicate-prefix path.
- The strict Rust decoder operates on parsed Bitcoin Script pushes and interprets the first lowercase tl followed by one base36 type byte. It leaves type-specific fields opaque.

The synthetic double-prefix example demonstrates this ambiguity:
tl1tl1a,COIN,,0,,0,0,

This is a constructed fixture based on reading the source. Historical broadcast of
that exact sequence remains unverified. The legacy decoder's returned payload is
also offset relative to the strict envelope body.

## Scanning starts seen in the source

The [main.js table](https://github.com/patrickdugan/tradelayer.js/blob/dca0888b827c5bc28fa9189bc9e1d507f5c5670c/src/main.js)
contains these candidate starts:

| Network | Mainnet | Testnet |
| --- | ---: | ---: |
| Bitcoin | 880000 | 3520000 |
| Dogecoin | 5520000 | 6815000 |
| Litecoin | 2819000 | 3082500 |

The source contains placeholder comments and different initialization
defaults. These are recorded as observed configuration values only.
Actual type activation is tracked separately in
[activation.js](https://github.com/patrickdugan/tradelayer.js/blob/dca0888b827c5bc28fa9189bc9e1d507f5c5670c/src/activation.js).

## Candidate historical transactions awaiting authentication

- c59fd0a35bc93979133cda1ae86c235428112c153fbdabed2cbc7ea86e60543f:
  cited as a token-trade transaction at block height 3395569 in the
  [TradeLayer API docs](https://docs.tradelayer.org/api_reference/endpoints).
  Neither raw bytes nor block inclusion has been authenticated for this harness.
- bc395db7a7a11b42e9711e192a860da2fffe64955cae6dd673e267532f328b3d:
  used by the [TradeLayer.js decoder test](https://github.com/patrickdugan/tradelayer.js/blob/dca0888b827c5bc28fa9189bc9e1d507f5c5670c/tests/decoderTest.js)
  with a height of 3496378. Chain and network status remain unverified.

Authenticated replay requires the full raw transaction, the chain/network,
block hash and height, transaction position, prevouts for sender resolution,
and a pinned JS state-root/validity oracle. Activation state must be derived
from verified historical evidence before selecting a consensus rule set.

## Running the synthetic fixture corpus

    cargo test --all-targets
    cargo run --bin replay_fixtures -- fixtures/tradelayer/replay_v1.json

Replay verifies declared output of both parsers and rejects altered expectations,
duplicate fixture IDs and unsupported manifest schema versions.
