//! Installed-budget paths only. Ordinary constructors/readers retain their policy.

use super::*;
use std::{ffi::OsStr, fs::OpenOptions};

impl ImmutableArchiveReader {
    /// Installs the SAME invocation budget BEFORE ancestor or staging traversal.
    pub fn open_bounded(root: &Path, budget: &ArchiveReadBudget) -> io::Result<Self> {
        #[cfg(not(unix))]
        {
            let _ = (root, budget);
            return Err(invalid("bounded local archive profile requires Unix"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
            budget.charge_observations(1)?;
            let root: PathBuf = Self::directory_path_with_budget(root, Some(budget))?;
            let before: std::fs::Metadata = std::fs::symlink_metadata(&root)?;
            if !before.is_dir() || before.file_type().is_symlink() {
                return Err(invalid(
                    "archive root must be an existing regular directory",
                ));
            }
            let directory: File = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_DIRECTORY)
                .open(&root)?;
            let held: std::fs::Metadata = directory.metadata()?;
            if !held.is_dir() || (held.dev(), held.ino()) != (before.dev(), before.ino()) {
                return Err(invalid("archive root changed while opening"));
            }
            Self::ensure_directory_with_budget(&root, &directory, Some(budget))?;
            budget.charge_observations(1)?;
            let staging_path: PathBuf = root.join(ARCHIVE_STAGING_DIRECTORY);
            let staging: Option<ArchiveStagingDirectory> =
                match std::fs::symlink_metadata(&staging_path) {
                    Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                        let staging_file: File = OpenOptions::new()
                            .read(true)
                            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_DIRECTORY)
                            .open(&staging_path)?;
                        Self::ensure_directory_with_budget(
                            &staging_path,
                            &staging_file,
                            Some(budget),
                        )?;
                        Some(ArchiveStagingDirectory {
                            path: staging_path,
                            directory: staging_file,
                        })
                    }
                    Ok(_) => {
                        return Err(invalid("archive staging role is not a regular directory"));
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                    Err(error) => return Err(error),
                };
            let archive: Self = Self {
                root,
                directory,
                staging,
                budget: Some(budget.clone()),
            };
            archive.ensure_attached()?;
            archive.validate_staging()?;
            Ok(archive)
        }
    }

    /// Installed local work budget; ordinary readers have none.
    #[must_use]
    pub fn read_budget(&self) -> Option<&ArchiveReadBudget> {
        self.budget.as_ref()
    }

    pub(super) fn observe(&self) -> io::Result<()> {
        if let Some(budget) = &self.budget {
            budget.charge_observations(1)?;
        }
        Ok(())
    }

    pub(super) fn check_name_bytes(&self, name: &OsStr) -> io::Result<()> {
        if let Some(budget) = &self.budget {
            budget.check()?;
            if name.len() > 251 {
                return Err(budget.refuse());
            }
        }
        Ok(())
    }

    pub(super) fn directory_path_with_budget(
        root: &Path,
        budget: Option<&ArchiveReadBudget>,
    ) -> io::Result<PathBuf> {
        let Some(budget) = budget else {
            return Self::directory_path(root);
        };
        budget.check()?;
        // No clone/collection of an unbounded component iterator before admission.
        let mut checked: PathBuf = if root.is_absolute() {
            PathBuf::new()
        } else {
            let current: PathBuf = std::env::current_dir()?;
            Self::directory_path_with_budget(&current, Some(budget))?
        };
        for component in root.components() {
            budget.charge_observations(1)?;
            match component {
                Component::Prefix(_) | Component::RootDir => checked.push(component),
                Component::CurDir => {}
                Component::ParentDir => {
                    return Err(invalid("archive root must not traverse parent components"));
                }
                Component::Normal(name) => {
                    if name.len() > 255 {
                        return Err(budget.refuse());
                    }
                    checked.push(component);
                    let metadata: std::fs::Metadata = std::fs::symlink_metadata(&checked)?;
                    if !metadata.is_dir() || metadata.file_type().is_symlink() {
                        return Err(invalid("archive root ancestor is not a regular directory"));
                    }
                }
            }
        }
        budget.check()?;
        Ok(checked)
    }

    pub(super) fn ensure_directory_with_budget(
        path: &Path,
        directory: &File,
        budget: Option<&ArchiveReadBudget>,
    ) -> io::Result<()> {
        let Some(budget) = budget else {
            return Self::ensure_directory_attached(path, directory);
        };
        Self::directory_path_with_budget(path, Some(budget))?;
        budget.charge_observations(1)?;
        let actual: std::fs::Metadata = std::fs::symlink_metadata(path)?;
        let held: std::fs::Metadata = directory.metadata()?;
        if !actual.is_dir() || actual.file_type().is_symlink() || !held.is_dir() {
            return Err(invalid("archive root was replaced"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if (actual.dev(), actual.ino()) != (held.dev(), held.ino()) {
                return Err(invalid("archive root was replaced"));
            }
        }
        budget.check()
    }

    /// Checks exact local relative locator shape without allocating a normalized name.
    pub fn relative_filename(name: &str) -> io::Result<&Path> {
        if name.is_empty()
            || name.len() > 251
            || name.contains(['\\', '\0'])
            || name
                .split('/')
                .any(|part: &str| part.is_empty() || part == "." || part == "..")
        {
            return Err(invalid("bounded archive locator differs"));
        }
        let path: &Path = Path::new(name);
        if path
            .components()
            .any(|part: Component<'_>| !matches!(part, Component::Normal(_)))
        {
            return Err(invalid(
                "bounded archive locator is not a normal relative path",
            ));
        }
        Ok(path)
    }

    /// Opens a nested attached leaf through this held role, never an unbounded path reader.
    /// The defining consumer must separately close/validate the complete generated inventory.
    pub fn open_file(&self, name: &str, maximum: u64) -> io::Result<AttachedRegularFile> {
        let budget: &ArchiveReadBudget = self
            .budget
            .as_ref()
            .ok_or_else(|| invalid("attached archive leaf requires an installed budget"))?;
        budget.charge_observations(1)?;
        let relative: &Path = Self::relative_filename(name)?;
        self.ensure_attached()?;
        let maximum: usize = usize::try_from(maximum).map_err(|_| budget.refuse())?;
        let maximum: u64 = budget.file_limit(maximum)?;
        let path: PathBuf = self.root.join(relative);
        let input: AttachedRegularFile =
            AttachedRegularFile::open(&path, maximum, budget, AttachedFilePolicy::public())?;
        self.ensure_attached()?;
        Ok(input)
    }

    /// Reads a generated nested file under the installed work budget.
    pub fn read_relative(&self, name: &str, maximum: usize) -> io::Result<Vec<u8>> {
        let budget: &ArchiveReadBudget = self
            .budget
            .as_ref()
            .ok_or_else(|| invalid("nested archive read requires an installed budget"))?;
        let mut input: AttachedRegularFile =
            self.open_file(name, u64::try_from(maximum).map_err(|_| budget.refuse())?)?;
        let length: u64 = input.stamp().length;
        let mut bytes: Vec<u8> = Vec::new();
        let mut buffer: [u8; 64 * 1024] = [0; 64 * 1024];
        loop {
            budget.check()?;
            let count: usize = input.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            let next: usize = bytes
                .len()
                .checked_add(count)
                .ok_or_else(|| budget.refuse())?;
            if u64::try_from(next).map_err(|_| budget.refuse())? > length {
                return Err(budget.refuse());
            }
            bytes
                .try_reserve_exact(count)
                .map_err(|_| budget.refuse())?;
            bytes.extend_from_slice(&buffer[..count]);
        }
        if u64::try_from(bytes.len()).map_err(|_| budget.refuse())? != length {
            return Err(invalid("bounded archive artifact changed length"));
        }
        input.ensure_attached()?;
        self.ensure_attached()?;
        Ok(bytes)
    }

    /// Complete nested inventory for bounded histories. Ignored valid staging bytes
    /// remain unread. Directory names are returned too, so empty/surplus directories
    /// cannot disappear from a consumer's closure check. No ordinary path is widened.
    pub fn names_recursive(&self) -> io::Result<BTreeSet<String>> {
        let budget: &ArchiveReadBudget = self
            .budget
            .as_ref()
            .ok_or_else(|| invalid("nested archive inventory requires an installed budget"))?;
        self.ensure_attached()?;
        let mut names: BTreeSet<String> = BTreeSet::new();
        self.walk_names("", 0, &mut names, budget)?;
        self.ensure_attached()?;
        Ok(names)
    }

    fn walk_names(
        &self,
        prefix: &str,
        depth: u8,
        names: &mut BTreeSet<String>,
        budget: &ArchiveReadBudget,
    ) -> io::Result<()> {
        budget.charge_observations(1)?;
        // The history layout has root/height/component, not arbitrary recursion.
        if depth > 2 {
            return Err(invalid("bounded history inventory is too deep"));
        }
        let path: PathBuf = self.root.join(prefix);
        let directory: File = Self::open_bounded_directory(&path, budget)?;
        for entry in std::fs::read_dir(&path)? {
            budget.charge_observations(1)?;
            let entry: std::fs::DirEntry = entry?;
            self.check_name_bytes(&entry.file_name())?;
            let leaf: String = entry
                .file_name()
                .into_string()
                .map_err(|_| invalid("archive filename is not UTF-8"))?;
            Self::filename(&leaf)?;
            let name: String = if prefix.is_empty() {
                leaf
            } else {
                format!("{prefix}/{leaf}")
            };
            Self::relative_filename(&name)?;
            let metadata: std::fs::Metadata = std::fs::symlink_metadata(entry.path())?;
            if depth == 0 && name == ARCHIVE_STAGING_DIRECTORY {
                if self.staging.is_none() || !metadata.is_dir() || metadata.file_type().is_symlink()
                {
                    return Err(invalid("archive staging role changed"));
                }
                self.validate_staging()?;
                continue;
            }
            if metadata.file_type().is_symlink() || (!metadata.is_file() && !metadata.is_dir()) {
                return Err(invalid(
                    "archive inventory contains a nonregular attachment",
                ));
            }
            if metadata.is_dir() {
                if depth >= 2 {
                    return Err(invalid("bounded history inventory is too deep"));
                }
                names.insert(format!("{name}/"));
                self.walk_names(&name, depth + 1, names, budget)?;
            } else {
                names.insert(name);
            }
        }
        Self::ensure_directory_with_budget(&path, &directory, Some(budget))
    }

    pub(super) fn open_bounded_directory(
        path: &Path,
        budget: &ArchiveReadBudget,
    ) -> io::Result<File> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            Self::directory_path_with_budget(path, Some(budget))?;
            let directory: File = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_DIRECTORY)
                .open(path)?;
            Self::ensure_directory_with_budget(path, &directory, Some(budget))?;
            Ok(directory)
        }
        #[cfg(not(unix))]
        {
            let _ = (path, budget);
            Err(invalid("bounded local archive profile requires Unix"))
        }
    }
}
