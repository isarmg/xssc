//! Exact current instance lock identities. These files are never restored.
use super::{UpgradePlan, execution, snapshot};
use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    os::{
        fd::AsFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Kind {
    File,
    Directory,
}
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct Declaration {
    pub path: PathBuf,
    pub kind: Kind,
}
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct Authority {
    pub path: PathBuf,
    pub kind: Kind,
    pub mode: u32,
    pub device: u64,
    pub inode: u64,
    pub uid: u32,
    pub gid: u32,
}
pub(super) struct Held {
    pub authority: Authority,
    pub file: File,
}
fn identity(path: &Path, file: &File, uid: u32, gid: u32, kind: Kind) -> anyhow::Result<Authority> {
    snapshot::require_path(path)?;
    let held = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    ensure!(
        (if kind == Kind::Directory {
            held.is_dir()
        } else {
            held.is_file()
                && held.nlink() == 1
                && held.uid() == uid
                && held.gid() == gid
                && held.mode() & 0o7777 == 0o600
        }) && !named.file_type().is_symlink()
            && held.dev() == named.dev()
            && held.ino() == named.ino(),
        "instance lock owner, mode or named inode differs"
    );
    Ok(Authority {
        path: path.to_owned(),
        kind,
        mode: held.mode() & 0o7777,
        device: held.dev(),
        inode: held.ino(),
        uid: held.uid(),
        gid: held.gid(),
    })
}
pub(super) fn acquire(
    plan: &UpgradePlan,
    paths: &[Declaration],
    business_roots: &[PathBuf],
    recorded: &[Authority],
) -> anyhow::Result<Vec<Held>> {
    ensure!(
        !paths.is_empty() && paths.len() <= 64,
        "runtime lock declaration exceeds bounds"
    );
    let unique = paths
        .iter()
        .map(|path| (&path.path, path.kind))
        .collect::<std::collections::BTreeMap<_, _>>();
    ensure!(unique.len() == paths.len(), "runtime locks repeat");
    let (uid, gid) = execution::identity(plan)?;
    let mut result = Vec::new();
    for (path, kind) in unique {
        ensure!(
            kind != Kind::Directory || business_roots.contains(path),
            "directory runtime lock is not a declared business root"
        );
        let file = OpenOptions::new()
            .read(true)
            .write(kind == Kind::File)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::NONBLOCK
                    | if kind == Kind::Directory {
                        rustix::fs::OFlags::DIRECTORY
                    } else {
                        rustix::fs::OFlags::empty()
                    })
                .bits() as i32,
            )
            .open(path)?;
        let authority = identity(path, &file, uid, gid, kind)?;
        if !recorded.is_empty() {
            ensure!(
                recorded.iter().find(|old| old.path == *path) == Some(&authority),
                "recorded runtime lock identity changed"
            );
        }
        rustix::fs::flock(
            file.as_fd(),
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .context("a declared instance remains busy")?;
        result.push(Held { authority, file });
    }
    ensure!(
        recorded.is_empty() || result.len() == recorded.len(),
        "runtime lock group differs"
    );
    Ok(result)
}
pub(super) fn verify(held: &[Held]) -> anyhow::Result<()> {
    for lock in held {
        ensure!(
            identity(
                &lock.authority.path,
                &lock.file,
                lock.authority.uid,
                lock.authority.gid,
                lock.authority.kind
            )? == lock.authority,
            "held runtime lock changed"
        );
    }
    Ok(())
}
pub(super) fn declarations(authorities: &[Authority]) -> Vec<Declaration> {
    authorities
        .iter()
        .map(|a| Declaration {
            path: a.path.clone(),
            kind: a.kind,
        })
        .collect()
}
pub(super) fn file_paths(authorities: &[Authority]) -> Vec<PathBuf> {
    authorities
        .iter()
        .filter(|a| a.kind == Kind::File)
        .map(|a| a.path.clone())
        .collect()
}
pub(super) fn directory_paths(authorities: &[Authority]) -> Vec<PathBuf> {
    authorities
        .iter()
        .filter(|a| a.kind == Kind::Directory)
        .map(|a| a.path.clone())
        .collect()
}
