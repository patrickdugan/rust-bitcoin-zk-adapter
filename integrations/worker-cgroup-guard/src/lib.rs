//! Linux cgroup-v2 preflight for expensive, separately built proof workers.
//! It checks an operator-created memory boundary before proof parsing or
//! STARK verification. This library does not create or manage a cgroup.
use std::{env, path::Path};

const MAX_MIB: u64 = 32 * 1024;
const MIN_MIB: u64 = 128;

/// Opt-in fail-closed check enabled by the gateway's process environment.
/// An unset guard preserves compatibility with development/mock workers.
pub fn enforce_optional_memory_limit() -> Result<(), String> {
    let raw = match env::var("SUPERNODE_REQUIRE_CGROUP_MAX_MIB") {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => return Ok(()),
        Err(_) => return Err("invalid cgroup memory limit environment".into()),
    };
    let max_mib: u64 = raw.parse().map_err(|_| "invalid cgroup MiB limit")?;
    if !(MIN_MIB..=MAX_MIB).contains(&max_mib) {
        return Err("cgroup memory MiB limit outside permitted range".into());
    }
    #[cfg(target_os = "linux")]
    {
        let self_cgroup = std::fs::read_to_string("/proc/self/cgroup")
            .map_err(|e| format!("cannot inspect current cgroup: {e}"))?;
        verify_linux_cgroup(
            Path::new("/sys/fs/cgroup"),
            &self_cgroup,
            max_mib * 1024 * 1024,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = max_mib;
        Err("hard cgroup proof-worker preflight requires Linux cgroup v2".into())
    }
}

/// A finite parent limit also constrains all its descendant processes.
/// Requiring zero swap bounds total anonymous allocation plus swap pressure.
/// The root path is the operator/kernel-mounted cgroup-v2 hierarchy.
#[cfg(target_os = "linux")]
fn verify_linux_cgroup(root: &Path, current: &str, max_bytes: u64) -> Result<(), String> {
    if !root.join("cgroup.controllers").is_file() {
        return Err("unified cgroup v2 mount unavailable".into());
    }
    let relative = current
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or("process has no cgroup v2 membership")?;
    let mut location = root.to_path_buf();
    for component in Path::new(relative).components() {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(segment) => location.push(segment),
            _ => return Err("unsafe process cgroup membership".into()),
        }
    }
    // In a cgroup namespace, /proc/self/cgroup may be rooted differently
    // from the cgroup2 mount. A finite mount-root limit is still an ancestor
    // cap. Otherwise fail closed when the resolved leaf is inaccessible.
    let candidates = if location.exists() {
        location
            .ancestors()
            .take_while(|p| p.starts_with(root))
            .collect::<Vec<_>>()
    } else {
        vec![root]
    };
    let mut limited = false;
    let mut swap_disabled = false;
    for dir in candidates {
        if let Ok(raw) = std::fs::read_to_string(dir.join("memory.max")) {
            if let Ok(n) = raw.trim().parse::<u64>() {
                if n > 0 && n <= max_bytes {
                    limited = true;
                }
            }
        }
        if let Ok(raw) = std::fs::read_to_string(dir.join("memory.swap.max")) {
            if raw.trim() == "0" {
                swap_disabled = true;
            }
        }
    }
    if !limited {
        return Err("proof worker has no finite cgroup memory.max within configured limit".into());
    }
    if !swap_disabled {
        return Err("proof worker cgroup must disable swap".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    #[test]
    fn cgroup_limit_rejects_unbounded_and_swap_enabled() {
        use std::{
            fs,
            time::{SystemTime, UNIX_EPOCH},
        };
        let root = env::temp_dir().join(format!(
            "supernode-cgroup-gate-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("node.service")).unwrap();
        fs::write(root.join("cgroup.controllers"), "memory pids io").unwrap();
        fs::write(root.join("memory.max"), "max").unwrap();
        fs::write(root.join("memory.swap.max"), "max").unwrap();
        fs::write(root.join("node.service/memory.max"), "536870912").unwrap();
        fs::write(root.join("node.service/memory.swap.max"), "0").unwrap();
        let profile = "0::/node.service\n";
        assert!(verify_linux_cgroup(&root, profile, 512 * 1024 * 1024).is_ok());
        assert!(verify_linux_cgroup(&root, profile, 128 * 1024 * 1024).is_err());
        fs::write(root.join("node.service/memory.swap.max"), "2048").unwrap();
        assert!(verify_linux_cgroup(&root, profile, 512 * 1024 * 1024).is_err());
        fs::write(root.join("node.service/memory.max"), "max").unwrap();
        fs::write(root.join("node.service/memory.swap.max"), "0").unwrap();
        assert!(verify_linux_cgroup(&root, profile, 512 * 1024 * 1024).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn root_limit_works_in_private_cgroup_namespace() {
        use std::{
            fs,
            time::{SystemTime, UNIX_EPOCH},
        };
        let root = env::temp_dir().join(format!(
            "supernode-cgroup-root-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("cgroup.controllers"), "memory").unwrap();
        fs::write(root.join("memory.max"), "268435456").unwrap();
        fs::write(root.join("memory.swap.max"), "0").unwrap();
        assert!(
            verify_linux_cgroup(&root, "0::/child-hidden-in-namespace", 512 * 1024 * 1024).is_ok()
        );
        assert!(verify_linux_cgroup(&root, "not a v2 cgroup", 512 * 1024 * 1024).is_err());
        assert!(verify_linux_cgroup(&root, "0::/../escape", 512 * 1024 * 1024).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
