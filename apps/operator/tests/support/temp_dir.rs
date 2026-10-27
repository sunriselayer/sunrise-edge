//! Std-only directory owner for tests with explicit prefix, tag and counter.

use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(prefix: &str, tag: &str, next: &AtomicU64) -> Self {
        let path: PathBuf = std::env::temp_dir().join(format!(
            "{prefix}-{tag}-{}-{}",
            std::process::id(),
            next.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ignored = std::fs::remove_dir_all(&self.0);
    }
}
