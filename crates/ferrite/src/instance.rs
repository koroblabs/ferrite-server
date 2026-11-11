//! One ferrite per config. A second one started by mistake — `ferrite` run by
//! hand to see what it is, say — would otherwise get as far as tearing down
//! the first one's WireGuard links (named the same, so taken for leftovers of
//! a previous run) before failing on port 53. So the lock is taken right after
//! the config is read, before anything touches the network.
//!
//! It is an flock on a file beside the config, held for the life of the
//! process. A restart in place execs the binary anew: the descriptor is
//! close-on-exec, so the lock goes with the old image and the new one takes
//! it again.

use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};

/// Held while the process lives; dropping it lets another ferrite start.
pub struct InstanceLock {
    _file: File,
}

/// What became of taking the lock.
pub enum Lock {
    Held(InstanceLock),
    /// Another ferrite holds it.
    Taken(PathBuf),
    /// No lock to be had (a read-only directory, a filesystem without
    /// locks): run anyway, as before there was one.
    Unavailable(String),
}

/// The lock file beside the config ferrite reads (or would write).
pub fn lock_path() -> PathBuf {
    let candidates = ferrite_core::config::Config::config_candidates();
    let config = candidates
        .iter()
        .find(|p| p.exists())
        .or(candidates.first())
        .cloned()
        .unwrap_or_else(|| PathBuf::from("config.toml"));
    config.parent().map_or_else(
        || PathBuf::from(".ferrite.lock"),
        |dir| dir.join(".ferrite.lock"),
    )
}

pub fn take(path: &Path) -> Lock {
    // Read-only is enough for an flock, and works on a file another user made.
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            match OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .open(path)
            {
                Ok(file) => file,
                Err(e) => return Lock::Unavailable(format!("{}: {e}", path.display())),
            }
        }
        Err(e) => return Lock::Unavailable(format!("{}: {e}", path.display())),
    };
    match file.try_lock() {
        Ok(()) => Lock::Held(InstanceLock { _file: file }),
        Err(TryLockError::WouldBlock) => Lock::Taken(path.to_path_buf()),
        Err(TryLockError::Error(e)) => Lock::Unavailable(format!("{}: {e}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_lock(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(".ferrite.lock")
    }

    #[test]
    fn a_second_ferrite_finds_the_lock_taken_until_the_first_is_gone() {
        let path = temp_lock("ferrite-instance");
        let Lock::Held(first) = take(&path) else {
            panic!("the first one gets the lock");
        };
        assert!(matches!(take(&path), Lock::Taken(p) if p == path));
        drop(first);
        assert!(
            matches!(take(&path), Lock::Held(_)),
            "free again once it's gone"
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn no_place_for_a_lock_is_no_reason_not_to_run() {
        let path = std::env::temp_dir()
            .join(format!("ferrite-no-such-dir-{}", std::process::id()))
            .join(".ferrite.lock");
        assert!(matches!(take(&path), Lock::Unavailable(_)));
    }
}
