//! Exact recursive byte observations of disposable input archives.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

pub fn snapshot(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    let mut files: BTreeMap<PathBuf, Option<Vec<u8>>> = BTreeMap::new();
    let mut pending: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).unwrap() {
            let path: PathBuf = entry.unwrap().path();
            let metadata: std::fs::Metadata = std::fs::symlink_metadata(&path).unwrap();
            assert!(!metadata.file_type().is_symlink());
            let relative: PathBuf = path.strip_prefix(root).unwrap().to_path_buf();
            let contents: Option<Vec<u8>> = if metadata.is_dir() {
                pending.push(path);
                None
            } else {
                assert!(metadata.is_file());
                Some(std::fs::read(&path).unwrap())
            };
            assert!(files.insert(relative, contents).is_none());
        }
    }
    files
}
