use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_ENTRIES: usize = 2_000_000;
const MAX_DEPTH: usize = 128;
const MAX_ACL_BYTES: usize = 64 * 1024;
const MAX_TOTAL_ACL_BYTES: usize = 32 * 1024 * 1024;
const ACCESS_ACL: &str = "system.posix_acl_access";
const DEFAULT_ACL: &str = "system.posix_acl_default";

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
    // Empty bytes record absence, including the need to remove ACLs inherited
    // while rebuilding a directory tree. Both fields are mandatory in journals.
    pub access_acl: Vec<u8>,
    pub default_acl: Vec<u8>,
    pub mtime_seconds: i64,
    pub mtime_nanoseconds: i64,
}

pub(super) fn ownership(root: &Path, entries: &[Entry]) -> anyhow::Result<Vec<Ownership>> {
    let mut total_acl_bytes = 0usize;
    entries
        .iter()
        .map(|entry| {
            let path = if entry.path.as_os_str().is_empty() {
                root.to_owned()
            } else {
                root.join(&entry.path)
            };
            let file = open_entry(&path, entry)?;
            let metadata = file.metadata()?;
            ensure!(
                metadata.mode() & 0o7777 == entry.mode,
                "state mode changed before ACL inventory"
            );
            let access_acl = read_acl(&file, ACCESS_ACL)?;
            let default_acl = if entry.directory {
                read_acl(&file, DEFAULT_ACL)?
            } else {
                Vec::new()
            };
            total_acl_bytes = total_acl_bytes
                .checked_add(access_acl.len())
                .and_then(|total| total.checked_add(default_acl.len()))
                .context("ACL inventory size overflow")?;
            ensure!(
                total_acl_bytes <= MAX_TOTAL_ACL_BYTES,
                "ACL inventory exceeds size limit"
            );
            ensure!(
                stable(&metadata, &file.metadata()?),
                "state permissions changed during ACL inventory"
            );
            Ok(Ownership {
                path: entry.path.clone(),
                uid: metadata.uid(),
                gid: metadata.gid(),
                access_acl,
                default_acl,
                mtime_seconds: metadata.mtime(),
                mtime_nanoseconds: metadata.mtime_nsec(),
            })
        })
        .collect()
}

pub(super) fn restore_ownership(
    root: &Path,
    entries: &[Entry],
    ownership: &[Ownership],
) -> anyhow::Result<()> {
    restore_permissions(root, entries, ownership, true)
}

fn open_entry(path: &Path, entry: &Entry) -> anyhow::Result<File> {
    require_path(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        if entry.directory {
            metadata.is_dir()
        } else {
            metadata.is_file() && metadata.nlink() == 1
        },
        "permission inventory resource type differs"
    );
    let named = fs::symlink_metadata(path)?;
    ensure!(
        named.dev() == metadata.dev() && named.ino() == metadata.ino(),
        "permission inventory resource identity changed"
    );
    Ok(file)
}

fn no_acl(error: rustix::io::Errno) -> bool {
    error == rustix::io::Errno::NODATA || error == rustix::io::Errno::OPNOTSUPP
}

fn read_acl(file: &File, name: &str) -> anyhow::Result<Vec<u8>> {
    let length = match rustix::fs::fgetxattr(file, name, &mut [0u8; 0]) {
        Ok(length) => length,
        Err(error) if no_acl(error) => return Ok(Vec::new()),
        Err(error) => return Err(error).with_context(|| format!("read bounded {name} size")),
    };
    ensure!(
        length > 0 && length <= MAX_ACL_BYTES,
        "POSIX ACL exceeds size limit"
    );
    let mut bytes = vec![0; length];
    let read = rustix::fs::fgetxattr(file, name, bytes.as_mut_slice())
        .with_context(|| format!("read bounded {name}"))?;
    ensure!(read == length, "POSIX ACL changed during inventory");
    Ok(bytes)
}

fn restore_acl(file: &File, name: &str, bytes: &[u8]) -> anyhow::Result<()> {
    ensure!(bytes.len() <= MAX_ACL_BYTES, "ACL exceeds size limit");
    if bytes.is_empty() {
        match rustix::fs::fremovexattr(file, name) {
            Ok(()) => {}
            Err(error) if no_acl(error) => {}
            Err(error) => return Err(error).with_context(|| format!("remove inherited {name}")),
        }
    } else {
        rustix::fs::fsetxattr(file, name, bytes, rustix::fs::XattrFlags::empty())
            .with_context(|| format!("restore {name}"))?;
    }
    ensure!(read_acl(file, name)? == bytes, "restored {name} differs");
    Ok(())
}

fn restore_permissions(
    root: &Path,
    entries: &[Entry],
    ownership: &[Ownership],
    final_metadata: bool,
) -> anyhow::Result<()> {
    validate_ownership(entries, ownership)?;
    for (entry, owner) in entries.iter().zip(ownership).rev() {
        let path = if entry.path.as_os_str().is_empty() {
            root.to_owned()
        } else {
            root.join(&entry.path)
        };
        let file = open_entry(&path, entry)?;
        let metadata = file.metadata()?;
        if metadata.uid() != owner.uid || metadata.gid() != owner.gid {
            rustix::fs::fchown(
                &file,
                Some(rustix::process::Uid::from_raw(owner.uid)),
                Some(rustix::process::Gid::from_raw(owner.gid)),
            )?;
        }
        if final_metadata {
            // A prior access ACL may grant a different UID access when chmod
            // widens its mask. Replace/remove it before publishing final mode.
            restore_acl(&file, ACCESS_ACL, &owner.access_acl)?;
            if entry.directory {
                restore_acl(&file, DEFAULT_ACL, &owner.default_acl)?;
            }
        }
        let mode = if !final_metadata && entry.directory {
            0o700
        } else {
            entry.mode
        };
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        if final_metadata {
            ensure!(
                read_acl(&file, ACCESS_ACL)? == owner.access_acl,
                "chmod changed the restored access ACL"
            );
            // Directory modification times must be restored after all children
            // exist. Access times are outside the persistent data contract.
            rustix::fs::futimens(
                &file,
                &rustix::fs::Timestamps {
                    last_access: rustix::fs::Timespec {
                        tv_sec: 0,
                        tv_nsec: rustix::fs::UTIME_OMIT,
                    },
                    last_modification: rustix::fs::Timespec {
                        tv_sec: owner.mtime_seconds,
                        tv_nsec: owner.mtime_nanoseconds,
                    },
                },
            )?;
        }
        let after = file.metadata()?;
        ensure!(
            after.uid() == owner.uid
                && after.gid() == owner.gid
                && after.mode() & 0o7777 == mode
                && (!final_metadata
                    || (after.mtime() == owner.mtime_seconds
                        && after.mtime_nsec() == owner.mtime_nanoseconds)),
            "restored ownership, mode or modification time differs"
        );
        file.sync_all()?;
    }
    sync_parent(root)
}

pub(super) fn validate_ownership(entries: &[Entry], ownership: &[Ownership]) -> anyhow::Result<()> {
    ensure!(
        entries.len() == ownership.len(),
        "ownership inventory length differs"
    );
    let mut total = 0usize;
    for (entry, owner) in entries.iter().zip(ownership) {
        ensure!(entry.path == owner.path, "ownership mapping differs");
        ensure!(
            (0..1_000_000_000).contains(&owner.mtime_nanoseconds),
            "invalid modification time nanoseconds"
        );
        ensure!(
            entry.mode & !0o777 == 0,
            "ownership mode exceeds resource contract"
        );
        ensure!(
            entry.directory || owner.default_acl.is_empty(),
            "file has a default ACL"
        );
        for (bytes, access) in [(&owner.access_acl, true), (&owner.default_acl, false)] {
            ensure!(bytes.len() <= MAX_ACL_BYTES, "ACL exceeds size limit");
            if !bytes.is_empty() {
                ensure!(
                    bytes.len() >= 28
                        && (bytes.len() - 4) % 8 == 0
                        && bytes[..4] == 2u32.to_le_bytes(),
                    "invalid Linux POSIX ACL encoding"
                );
                let mode = validate_acl(bytes)?;
                ensure!(
                    !access || mode == entry.mode,
                    "access ACL mode differs from inventory"
                );
            }
            total = total
                .checked_add(bytes.len())
                .context("ACL inventory size overflow")?;
        }
    }
    ensure!(
        total <= MAX_TOTAL_ACL_BYTES,
        "ACL inventory exceeds size limit"
    );
    Ok(())
}

fn validate_acl(bytes: &[u8]) -> anyhow::Result<u32> {
    let mut state = 0u8;
    let mut owner = None;
    let mut group = None;
    let mut mask = None;
    let mut other = None;
    let mut last_user = None;
    let mut last_group = None;
    for entry in bytes[4..].as_chunks::<8>().0 {
        let tag = u16::from_le_bytes(entry[..2].try_into()?);
        let permission = u16::from_le_bytes(entry[2..4].try_into()?);
        let id = u32::from_le_bytes(entry[4..].try_into()?);
        ensure!(permission <= 7, "invalid ACL permission bits");
        match tag {
            1 => {
                ensure!(state == 0 && id == u32::MAX, "invalid ACL owner entry");
                owner = Some(u32::from(permission));
                state = 1;
            }
            2 => {
                ensure!(
                    state == 1 && id != u32::MAX && last_user.is_none_or(|last| id > last),
                    "invalid ACL named user"
                );
                last_user = Some(id);
            }
            4 => {
                ensure!(state == 1 && id == u32::MAX, "invalid ACL group entry");
                group = Some(u32::from(permission));
                state = 2;
            }
            8 => {
                ensure!(
                    state == 2 && id != u32::MAX && last_group.is_none_or(|last| id > last),
                    "invalid ACL named group"
                );
                last_group = Some(id);
            }
            16 => {
                ensure!(state == 2 && id == u32::MAX, "invalid ACL mask entry");
                mask = Some(u32::from(permission));
                state = 3;
            }
            32 => {
                ensure!(
                    (state == 2 || state == 3) && id == u32::MAX,
                    "invalid ACL other entry"
                );
                other = Some(u32::from(permission));
                state = 4;
            }
            _ => anyhow::bail!("unknown POSIX ACL tag"),
        }
    }
    ensure!(
        state == 4 && (last_user.is_none() && last_group.is_none() || mask.is_some()),
        "incomplete POSIX ACL"
    );
    Ok((owner.context("ACL owner is missing")? << 6)
        | (mask.or(group).context("ACL group is missing")? << 3)
        | other.context("ACL other is missing")?)
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
    let stage = path.with_file_name(format!(".state-atomic-{}", uuid::Uuid::new_v4()));
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
    _primary: bool,
) -> anyhow::Result<Vec<Entry>> {
    let metadata = fs::symlink_metadata(root)?;
    let caller = rustix::process::geteuid().as_raw();
    ensure!(
        caller == 0 || caller == metadata.uid(),
        "state belongs to another user"
    );
    inventory_owned(root, directory, max_bytes, _primary, metadata.uid())
}

pub(super) fn inventory_owned(
    root: &Path,
    directory: bool,
    max_bytes: u64,
    _primary: bool,
    owner_uid: u32,
) -> anyhow::Result<Vec<Entry>> {
    require_path(root)?;
    let mut entries = Vec::new();
    let mut total = 0u64;
    visit(
        root,
        Path::new(""),
        directory,
        _primary,
        &mut entries,
        &mut total,
        max_bytes,
        0,
        owner_uid,
        false,
        false,
        &[],
    )?;
    Ok(entries)
}

/// The declared product helper has authorized this exact nonprivate business root.
/// Existing ownership and group-write permissions are part of its data contract.
pub(super) fn inventory_shared(
    root: &Path,
    directory: bool,
    max_bytes: u64,
) -> anyhow::Result<Vec<Entry>> {
    ensure!(
        rustix::process::geteuid().as_raw() == 0,
        "shared snapshots require the administrator tool"
    );
    require_path(root)?;
    let mut entries = Vec::new();
    visit(
        root,
        Path::new(""),
        directory,
        false,
        &mut entries,
        &mut 0,
        max_bytes,
        0,
        0,
        false,
        true,
        &[],
    )?;
    Ok(entries)
}

pub(super) fn inventory_preserving(
    root: &Path,
    directory: bool,
    max_bytes: u64,
    primary: bool,
    shared: bool,
    excluded: &[PathBuf],
) -> anyhow::Result<Vec<Entry>> {
    require_path(root)?;
    let mut entries = Vec::new();
    visit(
        root,
        Path::new(""),
        directory,
        primary,
        &mut entries,
        &mut 0,
        max_bytes,
        0,
        fs::symlink_metadata(root)?.uid(),
        false,
        shared,
        excluded,
    )?;
    Ok(entries)
}
#[allow(clippy::too_many_arguments)]
fn visit(
    root: &Path,
    relative: &Path,
    expect_directory: bool,
    _primary: bool,
    entries: &mut Vec<Entry>,
    total: &mut u64,
    max_bytes: u64,
    depth: usize,
    owner_uid: u32,
    administrative_restore: bool,
    shared: bool,
    excluded: &[PathBuf],
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
        shared
            || metadata.uid() == owner_uid
            || (administrative_restore
                && rustix::process::geteuid().as_raw() == 0
                && metadata.uid() == 0),
        "state must belong to the service user"
    );
    ensure!(
        metadata.mode() & if shared { 0o7002 } else { 0o7022 } == 0,
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
            if excluded.contains(&child.path()) {
                continue;
            }
            let metadata = fs::symlink_metadata(child.path())?;
            visit(
                root,
                &relative.join(child.file_name()),
                metadata.is_dir(),
                _primary,
                entries,
                total,
                max_bytes,
                depth + 1,
                owner_uid,
                administrative_restore,
                shared,
                excluded,
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
    snapshot_recorded(source, target, entries, |_, _| Ok(()))
}

pub(super) fn snapshot_recorded(
    source: &Path,
    target: &Path,
    entries: &[Entry],
    mut record: impl FnMut(&Path, &fs::Metadata) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
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
            if entry.path.as_os_str().is_empty() {
                record(&target, &fs::symlink_metadata(&target)?)?;
            }
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

/// Recovery requires the administrator to hold the installation tool lock and
/// keep all declared writers stopped with startup controlled by the OS.
#[cfg(test)]
pub(super) fn restore(
    source: &Path,
    target: &Path,
    entries: &[Entry],
    _primary: bool,
    max_bytes: u64,
    ownership: &[Ownership],
) -> anyhow::Result<()> {
    restore_with_policy(
        source,
        target,
        entries,
        _primary,
        max_bytes,
        ownership,
        false,
        &[],
        &[],
    )
}

#[cfg(test)]
pub(super) fn restore_shared(
    source: &Path,
    target: &Path,
    entries: &[Entry],
    max_bytes: u64,
    ownership: &[Ownership],
) -> anyhow::Result<()> {
    ensure!(
        rustix::process::geteuid().as_raw() == 0,
        "shared restoration requires the administrator tool"
    );
    restore_with_policy(
        source,
        target,
        entries,
        false,
        max_bytes,
        ownership,
        true,
        &[],
        &[],
    )
}

pub(super) struct Preserved<'a> {
    pub files: &'a [PathBuf],
    pub directories: &'a [PathBuf],
}
pub(super) fn restore_preserving(
    source: &Path,
    target: &Path,
    entries: &[Entry],
    max_bytes: u64,
    ownership: &[Ownership],
    shared: bool,
    preserved: Preserved<'_>,
) -> anyhow::Result<()> {
    ensure!(
        !preserved.files.contains(&target.to_owned()),
        "a runtime lock cannot be restored as a resource"
    );
    restore_with_policy(
        source,
        target,
        entries,
        false,
        max_bytes,
        ownership,
        shared,
        preserved.files,
        preserved.directories,
    )
}
fn clear_preserving(
    directory: &Path,
    excluded: &[PathBuf],
    directories: &[PathBuf],
) -> anyhow::Result<()> {
    for child in fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()? {
        let path = child.path();
        if excluded.contains(&path) {
            continue;
        }
        let info = fs::symlink_metadata(&path)?;
        ensure!(
            info.is_file() || info.is_dir(),
            "restore refuses aliases and special files"
        );
        if info.is_dir() {
            if excluded
                .iter()
                .chain(directories)
                .any(|item| item.starts_with(&path))
            {
                clear_preserving(&path, excluded, directories)?;
            } else {
                fs::remove_dir_all(&path)?;
            }
        } else {
            fs::remove_file(&path)?;
        }
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
fn restore_with_policy(
    source: &Path,
    target: &Path,
    entries: &[Entry],
    _primary: bool,
    max_bytes: u64,
    ownership: &[Ownership],
    shared: bool,
    excluded: &[PathBuf],
    directories: &[PathBuf],
) -> anyhow::Result<()> {
    require_path(target)?;
    validate_ownership(entries, ownership)?;
    if entries.first().is_some_and(|entry| entry.directory) {
        let mut current = Vec::new();
        // A prior root-driven restore can stop between creating and assigning
        // ownership. Only administrator-owned intermediate entries are
        // accepted, still under the same pending gate and exclusive lock.
        visit(
            target,
            Path::new(""),
            true,
            _primary,
            &mut current,
            &mut 0,
            max_bytes,
            0,
            ownership[0].uid,
            true,
            shared,
            excluded,
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
        clear_preserving(target, excluded, directories)?;
        for (entry, owner) in entries.iter().zip(ownership).skip(1) {
            let path = target.join(&entry.path);
            if entry.directory {
                if !named_exists(&path)? {
                    fs::DirBuilder::new().mode(0o700).create(&path)?;
                }
            } else {
                copy_regular(&source.join(&entry.path), &path, entry.mode)?;
            }
            restore_permissions(
                &path,
                &[Entry {
                    path: PathBuf::new(),
                    ..entry.clone()
                }],
                &[Ownership {
                    path: PathBuf::new(),
                    ..owner.clone()
                }],
                // An access ACL's mask can make a temporary 0700 directory
                // read-only. Restore exact ACLs only after its children exist.
                !entry.directory,
            )?;
        }
    } else {
        if named_exists(target)? {
            if shared {
                inventory_shared(target, false, max_bytes)?;
            } else {
                inventory(target, false, max_bytes, false)?;
            }
        }
        let stage = target.with_file_name(format!(".state-atomic-{}", uuid::Uuid::new_v4()));
        copy_regular(source, &stage, entries[0].mode)?;
        restore_ownership(&stage, entries, ownership)?;
        fs::rename(stage, target)?;
        sync_parent(target)?;
    }
    restore_ownership(target, entries, ownership)?;
    Ok(())
}
