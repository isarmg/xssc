use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(super) const PENDING: &str = xcsc::state_file::MAINTENANCE_PENDING_FILE;
pub(super) const COORDINATOR: &str = ".xssc.lock";
const RESERVED: [&str; 4] = [
    PENDING,
    ".state-maintenance.lock",
    ".state-instance.lock",
    COORDINATOR,
];
const MAX_ENTRIES: usize = 2_000_000;
const MAX_DEPTH: usize = 128;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Entry {
    pub path: PathBuf,
    pub directory: bool,
    pub mode: u32,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Ownership {
    pub path: PathBuf,
    pub uid: u32,
    pub gid: u32,
}

pub(super) fn ownership(root: &Path, entries: &[Entry]) -> anyhow::Result<Vec<Ownership>> {
    entries
        .iter()
        .map(|entry| {
            let path = if entry.path.as_os_str().is_empty() {
                root.to_owned()
            } else {
                root.join(&entry.path)
            };
            let metadata = fs::symlink_metadata(path)?;
            Ok(Ownership {
                path: entry.path.clone(),
                uid: metadata.uid(),
                gid: metadata.gid(),
            })
        })
        .collect()
}

pub(super) fn restore_ownership(
    root: &Path,
    entries: &[Entry],
    ownership: &[Ownership],
) -> anyhow::Result<()> {
    ensure!(
        entries.len() == ownership.len(),
        "ownership inventory length differs"
    );
    for (entry, owner) in entries.iter().zip(ownership).rev() {
        ensure!(
            entry.path.as_os_str() == owner.path.as_os_str(),
            "ownership mapping differs"
        );
        let path = if entry.path.as_os_str().is_empty() {
            root.to_owned()
        } else {
            root.join(&entry.path)
        };
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&path)?;
        let metadata = file.metadata()?;
        if metadata.uid() != owner.uid || metadata.gid() != owner.gid {
            rustix::fs::fchown(
                &file,
                Some(rustix::process::Uid::from_raw(owner.uid)),
                Some(rustix::process::Gid::from_raw(owner.gid)),
            )?;
        }
        file.set_permissions(fs::Permissions::from_mode(entry.mode))?;
        file.sync_all()?;
    }
    sync_parent(root)
}

pub(super) fn require_path(path: &Path) -> anyhow::Result<()> {
    ensure!(path.is_absolute(), "path must be absolute");
    ensure!(
        path.components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
            && path.components().collect::<PathBuf>().as_os_str() == path.as_os_str(),
        "path must be normalized"
    );
    let mut prefix = PathBuf::new();
    for component in path.components() {
        prefix.push(component);
        if let Ok(metadata) = fs::symlink_metadata(&prefix) {
            ensure!(
                !metadata.file_type().is_symlink(),
                "symbolic links are not accepted"
            );
        }
    }
    Ok(())
}

/// Unlike Path::try_exists this never follows a dangling symbolic link.
pub(super) fn named_exists(path: &Path) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                !metadata.file_type().is_symlink(),
                "unexpected symbolic link"
            );
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn open_regular(path: &Path) -> anyhow::Result<File> {
    require_path(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.nlink() == 1,
        "expected a regular file with one link"
    );
    let named = fs::symlink_metadata(path)?;
    ensure!(
        named.dev() == metadata.dev() && named.ino() == metadata.ino(),
        "file identity changed"
    );
    Ok(file)
}

pub(super) fn read_bounded(path: &Path, limit: u64) -> anyhow::Result<Vec<u8>> {
    let file = open_regular(path)?;
    ensure!(file.metadata()?.len() <= limit, "file exceeds size limit");
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit, "file exceeds size limit");
    Ok(bytes)
}

pub(super) fn digest_file(path: &Path) -> anyhow::Result<String> {
    let mut file = open_regular(path)?;
    let before = file.metadata()?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 128 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    let after = file.metadata()?;
    ensure!(stable(&before, &after), "file changed during verification");
    Ok(super::digest_hex(digest.finalize()))
}

fn stable(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

pub(super) fn private_directory(path: &Path) -> anyhow::Result<()> {
    require_path(path)?;
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(path)?;
    sync_parent(path)
}

pub(super) fn sync_directory(path: &Path) -> anyhow::Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

pub(super) fn sync_parent(path: &Path) -> anyhow::Result<()> {
    sync_directory(path.parent().context("path has no parent")?)
}

pub(super) fn atomic_json(path: &Path, value: &impl Serialize) -> anyhow::Result<()> {
    require_path(path)?;
    let stage = path.with_file_name(format!(".upgrade-json-{}", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&stage)?;
        serde_json::to_writer(&mut file, value)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&stage, path)?;
        sync_parent(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(stage);
    }
    result
}

pub(super) fn copy_regular(source: &Path, target: &Path, mode: u32) -> anyhow::Result<()> {
    let mut input = open_regular(source)?;
    let before = input.metadata()?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(target)?;
    let bytes = std::io::copy(&mut input, &mut output)?;
    ensure!(
        bytes == before.len() && stable(&before, &input.metadata()?),
        "source changed while copying"
    );
    output.set_permissions(fs::Permissions::from_mode(mode & 0o777))?;
    output.sync_all()?;
    sync_parent(target)
}

pub(super) fn inventory(
    root: &Path,
    directory: bool,
    max_bytes: u64,
    primary: bool,
) -> anyhow::Result<Vec<Entry>> {
    let metadata = fs::symlink_metadata(root)?;
    let caller = rustix::process::geteuid().as_raw();
    ensure!(
        caller == 0 || caller == metadata.uid(),
        "state belongs to another user"
    );
    inventory_owned(root, directory, max_bytes, primary, metadata.uid())
}

pub(super) fn inventory_owned(
    root: &Path,
    directory: bool,
    max_bytes: u64,
    primary: bool,
    owner_uid: u32,
) -> anyhow::Result<Vec<Entry>> {
    require_path(root)?;
    let mut entries = Vec::new();
    let mut total = 0u64;
    visit(
        root,
        Path::new(""),
        directory,
        primary,
        &mut entries,
        &mut total,
        max_bytes,
        0,
        owner_uid,
        false,
    )?;
    Ok(entries)
}

#[allow(clippy::too_many_arguments)]
fn visit(
    root: &Path,
    relative: &Path,
    expect_directory: bool,
    primary: bool,
    entries: &mut Vec<Entry>,
    total: &mut u64,
    max_bytes: u64,
    depth: usize,
    owner_uid: u32,
    administrative_restore: bool,
) -> anyhow::Result<()> {
    ensure!(
        depth <= MAX_DEPTH && entries.len() < MAX_ENTRIES,
        "state tree exceeds entry/depth limit"
    );
    let path = if relative.as_os_str().is_empty() {
        root.to_path_buf()
    } else {
        root.join(relative)
    };
    let metadata = fs::symlink_metadata(&path)?;
    ensure!(
        metadata.is_dir() == expect_directory,
        "resource type differs from release contract"
    );
    ensure!(
        metadata.is_file() || metadata.is_dir(),
        "special files and symlinks are not accepted"
    );
    ensure!(
        metadata.uid() == owner_uid
            || (administrative_restore
                && rustix::process::geteuid().as_raw() == 0
                && metadata.uid() == 0),
        "state must belong to the service user"
    );
    ensure!(
        metadata.mode() & 0o6022 == 0,
        "state cannot be writable by other users or setuid/setgid"
    );
    let (bytes, sha256) = if expect_directory {
        (0, String::new())
    } else {
        *total = total
            .checked_add(metadata.len())
            .context("state size overflow")?;
        ensure!(*total <= max_bytes, "state exceeds declared backup limit");
        (metadata.len(), digest_file(&path)?)
    };
    entries.push(Entry {
        path: relative.to_owned(),
        directory: expect_directory,
        mode: metadata.mode() & 0o777,
        bytes,
        sha256,
    });
    if expect_directory {
        let remaining = MAX_ENTRIES.saturating_sub(entries.len());
        let mut children = fs::read_dir(&path)?
            .take(remaining.saturating_add(1))
            .collect::<Result<Vec<_>, _>>()?;
        ensure!(
            children.len() <= remaining,
            "state tree exceeds entry limit"
        );
        children.sort_by_key(|entry| entry.file_name());
        for child in children {
            if primary
                && relative.as_os_str().is_empty()
                && RESERVED.iter().any(|name| child.file_name() == *name)
            {
                continue;
            }
            let metadata = fs::symlink_metadata(child.path())?;
            visit(
                root,
                &relative.join(child.file_name()),
                metadata.is_dir(),
                primary,
                entries,
                total,
                max_bytes,
                depth + 1,
                owner_uid,
                administrative_restore,
            )?;
        }
        let after = fs::symlink_metadata(&path)?;
        ensure!(
            stable(&metadata, &after),
            "directory changed during inventory"
        );
    }
    Ok(())
}

pub(super) fn snapshot(source: &Path, target: &Path, entries: &[Entry]) -> anyhow::Result<()> {
    for entry in entries {
        let source = if entry.path.as_os_str().is_empty() {
            source.to_path_buf()
        } else {
            source.join(&entry.path)
        };
        let target = if entry.path.as_os_str().is_empty() {
            target.to_path_buf()
        } else {
            target.join(&entry.path)
        };
        if entry.directory {
            let mut builder = fs::DirBuilder::new();
            // A complete immutable release may contain 0555 directories. Keep
            // newly created staging directories writable until all children
            // are copied, then seal them from leaves to root.
            builder.mode(0o700).create(&target)?;
            sync_parent(&target)?;
        } else {
            copy_regular(&source, &target, entry.mode)?;
            ensure!(
                digest_file(&target)? == entry.sha256,
                "backup contents changed"
            );
        }
    }
    for entry in entries.iter().rev().filter(|entry| entry.directory) {
        let directory = if entry.path.as_os_str().is_empty() {
            target.to_path_buf()
        } else {
            target.join(&entry.path)
        };
        fs::set_permissions(&directory, fs::Permissions::from_mode(entry.mode))?;
        sync_directory(&directory)?;
    }
    Ok(())
}

/// Recovery is repeatable only while the caller owns maintenance and the pending
/// gate. Lock files and the gate retain their inodes throughout restoration.
pub(super) fn restore(
    source: &Path,
    target: &Path,
    entries: &[Entry],
    primary: bool,
    max_bytes: u64,
    ownership: &[Ownership],
) -> anyhow::Result<()> {
    require_path(target)?;
    ensure!(
        entries.len() == ownership.len()
            && entries
                .iter()
                .zip(ownership)
                .all(|(entry, owner)| entry.path.as_os_str() == owner.path.as_os_str()),
        "restore ownership mapping differs"
    );
    if entries.first().is_some_and(|entry| entry.directory) {
        let mut current = Vec::new();
        // A prior root-driven restore can stop between creating and assigning
        // ownership. Only administrator-owned intermediate entries are
        // accepted, still under the same pending gate and exclusive lock.
        visit(
            target,
            Path::new(""),
            true,
            primary,
            &mut current,
            &mut 0,
            max_bytes,
            0,
            ownership[0].uid,
            true,
        )?;
        // Make only verified owned directories writable during this authorized
        // restoration. No path aliases or special files reach deletion.
        for entry in current.iter().filter(|entry| entry.directory) {
            let directory = if entry.path.as_os_str().is_empty() {
                target.to_path_buf()
            } else {
                target.join(&entry.path)
            };
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
        for child in fs::read_dir(target)?.collect::<Result<Vec<_>, _>>()? {
            if primary && RESERVED.iter().any(|name| child.file_name() == *name) {
                continue;
            }
            let metadata = fs::symlink_metadata(child.path())?;
            ensure!(
                !metadata.file_type().is_symlink(),
                "recovery refuses symbolic links"
            );
            if metadata.is_dir() {
                fs::remove_dir_all(child.path())?;
            } else {
                ensure!(metadata.is_file(), "recovery refuses special files");
                fs::remove_file(child.path())?;
            }
        }
        for (entry, owner) in entries.iter().zip(ownership).skip(1) {
            let path = target.join(&entry.path);
            if entry.directory {
                fs::DirBuilder::new().mode(0o700).create(&path)?;
            } else {
                copy_regular(&source.join(&entry.path), &path, entry.mode)?;
            }
            restore_ownership(
                &path,
                &[Entry {
                    path: PathBuf::new(),
                    // Keep directories writable until their children have
                    // been restored; the reverse pass below seals them.
                    mode: if entry.directory { 0o700 } else { entry.mode },
                    ..entry.clone()
                }],
                &[Ownership {
                    path: PathBuf::new(),
                    ..owner.clone()
                }],
            )?;
        }
        for entry in entries.iter().rev().filter(|entry| entry.directory) {
            let directory = if entry.path.as_os_str().is_empty() {
                target.to_path_buf()
            } else {
                target.join(&entry.path)
            };
            fs::set_permissions(&directory, fs::Permissions::from_mode(entry.mode))?;
            sync_directory(&directory)?;
        }
    } else {
        if named_exists(target)? {
            inventory(target, false, max_bytes, false)?;
        }
        let stage = target.with_file_name(format!(".upgrade-restore-{}", uuid::Uuid::new_v4()));
        copy_regular(source, &stage, entries[0].mode)?;
        restore_ownership(&stage, entries, ownership)?;
        fs::rename(stage, target)?;
        sync_parent(target)?;
    }
    restore_ownership(target, entries, ownership)?;
    Ok(())
}
