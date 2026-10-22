# Fixture provenance and verification

**Network distinctions matter.** Confirmed Bitcoin mainnet vectors below are generic Bitcoin transaction parsing examples. Script-only examples establish parsing expectations but cannot authenticate TXIDs or block membership by themselves. The regtest vector is from a public Bitcoin Core example rather than a confirmed mainnet block.

| Vector | Provenance | Expected check |
| --- | --- | --- |
| `fixtures/mainnet/2033435d....hex` | [Learn Me a Bitcoin](https://learnmeabitcoin.com/explorer/tx/2033435de7ce307341231e818ed937cd3a5e8597381fd83a7e5b0234f61b38d3), Bitcoin block 900,044 | 275 bytes; double-SHA256 gives TXID `2033435de7ce307341231e818ed937cd3a5e8597381fd83a7e5b0234f61b38d3`; vout 1 is an OP_RETURN with 60 NUL bytes and `learnmeabitcoin` |
| `fixtures/mainnet/b6abffe....script.hex` | [On-chain OP_RETURN research](https://github.com/merendamattia/op-return-tracking-message-bitcoin), block 328,455, vout 2 | 38-byte direct data push |
| `fixtures/mainnet/c89bebd....script.hex` | [On-chain OP_RETURN research](https://github.com/goga-m/btc-opreturn), source associates with TXID `c89bebdcaf9ee70d0dbb5d8e5e94349ff4446a396097716cb1bdd4ccd29f7208` | 80-byte OP_PUSHDATA1; block height and vout unprovided |
| `fixtures/regtest/00fddd....hex` | [Bitcoin Core decoderawtransaction example](https://bitcoin.stackexchange.com/questions/116869/how-can-i-recognize-an-op-return-transaction-looking-only-at-the-hex) | 246-byte SegWit transaction; regtest TXID `00fddd900b735a88ab0ef5eeaa3efbc869d4e52493da8a9467ec782355cb39ff` |

The mainnet transaction bytes were independently double-SHA256 hashed to the published txid before committing, and the CI suite verifies the txid using `bitcoin::Transaction::compute_txid()`. Raw hex avoids losing byte identity through JSON.

