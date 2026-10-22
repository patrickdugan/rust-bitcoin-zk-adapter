//! Offline fixture verifier; no wallet operations or network requests.
use rust_bitcoin_zk_adapter::replay::{run_fixture_set, FixtureSet};
use std::{env, error::Error, fs};
const MAX_MANIFEST_BYTES: u64 = 2_000_000;
fn main() -> Result<(), Box<dyn Error>> {
    let file = env::args()
        .nth(1)
        .ok_or("usage: replay_fixtures PATH_TO_JSON")?;
    if fs::metadata(&file)?.len() > MAX_MANIFEST_BYTES {
        return Err("manifest exceeds size limit".into());
    }
    let set: FixtureSet = serde_json::from_str(&fs::read_to_string(file)?)?;
    let checked = run_fixture_set(&set)?;
    println!("replay fixtures: {checked} matched strict and legacy expectations");
    Ok(())
}
