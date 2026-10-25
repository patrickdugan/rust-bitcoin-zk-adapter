//! Process group lifecycle for trusted prover and verifier binaries.
//! In Linux/Unix, a fresh group lets us terminate descendants on timeout,
//! cancellation, panic, or worker exit. Cgroups remain necessary for hard RSS.
use std::{process::ExitStatus, time::Duration};
use tokio::{process::Command, time::timeout};

#[cfg(unix)]
struct ProcessGroupCleanup(nix::unistd::Pid);

#[cfg(unix)]
impl Drop for ProcessGroupCleanup {
    fn drop(&mut self) {
        // The worker was launched in a group with its PID as the PGID.
        // Retire lingering children even after the group leader exits.
        let _ = nix::sys::signal::killpg(self.0, nix::sys::signal::Signal::SIGKILL);
    }
}

pub async fn run_supervised(mut command: Command, budget: Duration) -> Result<ExitStatus, String> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.as_std_mut().process_group(0);
    }
    command.kill_on_drop(true);
    let mut child = command.spawn().map_err(|error| error.to_string())?;
    #[cfg(unix)]
    let _group_cleanup = {
        let pid = child.id().ok_or("spawned worker process has no PID")?;
        let pid = i32::try_from(pid).map_err(|_| "worker PID is outside i32 range")?;
        ProcessGroupCleanup(nix::unistd::Pid::from_raw(pid))
    };
    timeout(budget, child.wait())
        .await
        .map_err(|_| "worker process runtime budget exceeded".to_owned())?
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[tokio::test]
    async fn parent_success_still_terminates_background_worker() {
        use std::{
            fs,
            time::{SystemTime, UNIX_EPOCH},
        };
        let marker = std::env::temp_dir().join(format!(
            "supernode-worker-orphan-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut command = Command::new("/bin/sh");
        // Exit successfully after observing that the background worker has
        // started. Group cleanup must still retire that process.
        command
            .arg("-c")
            .arg("(while :; do printf x >> \"$1\"; sleep 0.05; done) & while [ ! -s \"$1\" ]; do sleep 0.01; done; exit 0")
            .arg("worker-orphan-test")
            .arg(&marker);
        let status = run_supervised(command, Duration::from_secs(4))
            .await
            .unwrap();
        assert!(status.success());
        tokio::time::sleep(Duration::from_millis(150)).await;
        let before = fs::metadata(&marker).unwrap().len();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(fs::metadata(&marker).unwrap().len(), before);
        fs::remove_file(marker).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cancelling_supervision_terminates_background_worker() {
        use std::{
            fs,
            time::{SystemTime, UNIX_EPOCH},
        };
        let marker = std::env::temp_dir().join(format!(
            "supernode-worker-cancel-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("while :; do printf x >> \"$1\"; sleep 0.05; done & wait")
            .arg("worker-cancel-test")
            .arg(&marker);
        let task = tokio::spawn(run_supervised(command, Duration::from_secs(10)));
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if fs::metadata(&marker).is_ok_and(|meta| meta.len() > 0) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        tokio::time::sleep(Duration::from_millis(150)).await;
        let before = fs::metadata(&marker).unwrap().len();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(fs::metadata(&marker).unwrap().len(), before);
        fs::remove_file(marker).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_terminates_background_grandchildren() {
        use std::{
            fs,
            time::{SystemTime, UNIX_EPOCH},
        };
        let marker = std::env::temp_dir().join(format!(
            "supernode-child-liveness-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("while :; do printf x >> \"$1\"; sleep 0.05; done & wait")
            .arg("worker-liveness-test")
            .arg(&marker);
        assert!(run_supervised(command, Duration::from_millis(450))
            .await
            .is_err());
        assert!(marker.exists());
        // Give SIGKILL time to retire the process group before comparing the
        // heartbeat. A surviving grandchild would keep appending bytes.
        tokio::time::sleep(Duration::from_millis(150)).await;
        let before = fs::metadata(&marker).unwrap().len();
        tokio::time::sleep(Duration::from_millis(250)).await;
        let after = fs::metadata(&marker).unwrap().len();
        assert!(before > 0);
        assert_eq!(before, after);
        fs::remove_file(marker).unwrap();
    }
}
