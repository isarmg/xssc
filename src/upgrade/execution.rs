//! Inode-bound authority for administrator-owned upgrade work and staging.
use super::{UpgradeJournal, UpgradePlan, snapshot};
use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};
use xcsc::state_file::PrivateStateDirectory;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StageAuthority {
    pub root: PathBuf,
    pub parent_device: u64,
    pub parent_inode: u64,
    pub directory_device: u64,
    pub directory_inode: u64,
}

pub(super) fn identity(plan: &UpgradePlan) -> anyhow::Result<(u32, u32)> {
    let directory = PrivateStateDirectory::open_for_administration(&plan.data_dir)?;
    directory.verify_identity()?;
    Ok((directory.owner_uid(), directory.owner_gid()))
}

pub(super) fn verify_service(plan: &UpgradePlan) -> anyhow::Result<()> {
    let bytes = super::run_bounded(
        "/usr/bin/systemctl",
        &[
            "show".into(),
            plan.service.clone(),
            "--property=User".into(),
            "--property=Group".into(),
            "--property=DynamicUser".into(),
        ],
        plan.timeout_seconds,
    )?;
    let value = std::str::from_utf8(&bytes)?;
    let user = value
        .lines()
        .find_map(|line| line.strip_prefix("User="))
        .context("service User authority missing")?;
    let group = value
        .lines()
        .find_map(|line| line.strip_prefix("Group="))
        .context("service Group authority missing")?;
    ensure!(
        !value.lines().any(|line| line == "DynamicUser=yes"),
        "dynamic service identities are not supported"
    );
    let (uid, default_gid) = account(user)?;
    let gid = if group.is_empty() {
        default_gid
    } else {
        group_id(group)?
    };
    ensure!(
        (uid, gid) == identity(plan)?,
        "systemd service identity differs from the private data owner"
    );
    Ok(())
}

#[allow(unsafe_code)] // Reentrant NSS lookup; see docs/unsafe-audit.md.
fn account(name: &str) -> anyhow::Result<(u32, u32)> {
    if name.is_empty() {
        return Ok((0, 0));
    }
    let mut storage = vec![0u8; 65536];
    let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut pointer = std::ptr::null_mut();
    let cname = std::ffi::CString::new(name)?;
    // SAFETY: CString and both output buffers live through the reentrant NSS
    // call. The initialized passwd result is read only after success, and NSS
    // must return the exact output pointer supplied to it.
    let result = unsafe {
        if let Ok(uid) = name.parse::<u32>() {
            libc::getpwuid_r(
                uid,
                entry.as_mut_ptr(),
                storage.as_mut_ptr().cast(),
                storage.len(),
                &mut pointer,
            )
        } else {
            libc::getpwnam_r(
                cname.as_ptr(),
                entry.as_mut_ptr(),
                storage.as_mut_ptr().cast(),
                storage.len(),
                &mut pointer,
            )
        }
    };
    ensure!(
        result == 0 && pointer == entry.as_mut_ptr(),
        "service account cannot be resolved"
    );
    // SAFETY: successful NSS lookup above initialized this exact output value.
    let entry = unsafe { entry.assume_init() };
    Ok((entry.pw_uid, entry.pw_gid))
}

#[allow(unsafe_code)] // Reentrant NSS lookup; see docs/unsafe-audit.md.
fn group_id(name: &str) -> anyhow::Result<u32> {
    if let Ok(gid) = name.parse::<u32>() {
        return Ok(gid);
    }
    let mut storage = vec![0u8; 65536];
    let mut entry = std::mem::MaybeUninit::<libc::group>::uninit();
    let mut pointer = std::ptr::null_mut();
    let cname = std::ffi::CString::new(name)?;
    // SAFETY: the NUL-terminated input and bounded scratch/output storage remain
    // valid for the reentrant NSS call; its result pointer is checked below.
    let result = unsafe {
        libc::getgrnam_r(
            cname.as_ptr(),
            entry.as_mut_ptr(),
            storage.as_mut_ptr().cast(),
            storage.len(),
            &mut pointer,
        )
    };
    ensure!(
        result == 0 && pointer == entry.as_mut_ptr(),
        "service group cannot be resolved"
    );
    // SAFETY: successful NSS lookup above initialized this exact output value.
    Ok(unsafe { entry.assume_init() }.gr_gid)
}

/// This check is also used by the subprocess boundary. Private maintenance
/// paths need no service-user traversal permission: helpers run as root.
pub(super) fn require_trusted(path: &Path) -> anyhow::Result<()> {
    snapshot::require_path(path)?;
    let mut prefix = PathBuf::new();
    for component in path.components() {
        prefix.push(component);
        let metadata = fs::symlink_metadata(&prefix)?;
        ensure!(
            metadata.is_dir()
                && metadata.uid() == 0
                && (metadata.mode() & 0o022 == 0
                    || (metadata.mode() & 0o1000 != 0 && prefix == Path::new("/tmp"))),
            "maintenance ancestry must be administrator controlled"
        );
    }
    Ok(())
}

fn work_parent(plan: &UpgradePlan) -> anyhow::Result<PathBuf> {
    let native = plan
        .native_release
        .as_ref()
        .context("fixed-root plan required")?;
    let parent = native.root.join("maintenance/upgrades");
    let encoded = plan
        .work_directory
        .file_name()
        .and_then(|s| s.to_str())
        .context("work directory needs an operation UUID")?;
    let operation = uuid::Uuid::parse_str(encoded)?;
    ensure!(
        operation.get_version_num() == 4
            && operation.to_string() == encoded
            && plan.work_directory.parent() == Some(parent.as_path()),
        "work directory must be ROOT/maintenance/upgrades/canonical-v4-UUID"
    );
    Ok(parent)
}

fn private_metadata(path: &Path) -> anyhow::Result<fs::Metadata> {
    require_trusted(path)?;
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o7777 == 0o700,
        "upgrade control directory must be root-owned mode 0700"
    );
    Ok(metadata)
}

/// Capture creation authority before the first durable journal is published.
/// This seal survives target-payload cleanup and governs later collection.
pub(super) fn work_authority(plan: &UpgradePlan) -> anyhow::Result<StageAuthority> {
    ensure!(
        rustix::process::geteuid().as_raw() == 0,
        "upgrade requires root"
    );
    let parent = work_parent(plan)?;
    let parent_metadata = private_metadata(&parent)?;
    let directory = private_metadata(&plan.work_directory)?;
    Ok(StageAuthority {
        root: plan.work_directory.clone(),
        parent_device: parent_metadata.dev(),
        parent_inode: parent_metadata.ino(),
        directory_device: directory.dev(),
        directory_inode: directory.ino(),
    })
}

pub(super) fn verify_work(journal: &UpgradeJournal) -> anyhow::Result<()> {
    let seal = journal
        .work_directory_seal
        .as_ref()
        .context("work creation authority missing")?;
    let expected = work_authority(&journal.plan)?;
    ensure!(
        journal
            .plan
            .work_directory
            .file_name()
            .and_then(|s| s.to_str())
            == Some(journal.operation_id.to_string().as_str())
            && seal.root == expected.root
            && seal.parent_device == expected.parent_device
            && seal.parent_inode == expected.parent_inode
            && seal.directory_device == expected.directory_device
            && seal.directory_inode == expected.directory_inode,
        "upgrade work directory identity changed"
    );
    Ok(())
}

pub(super) fn prepare(journal: &mut UpgradeJournal) -> anyhow::Result<()> {
    verify_work(journal)
}

fn verify_payload(journal: &UpgradeJournal, allow_removed: bool) -> anyhow::Result<()> {
    verify_work(journal)?;
    let Some(seal) = &journal.payload_stage_seal else {
        return Ok(());
    };
    let parent = &journal.plan.work_directory;
    ensure!(
        seal.root == parent.join("target-payload"),
        "payload staging root mapping differs"
    );
    let parent_metadata = private_metadata(parent)?;
    ensure!(
        parent_metadata.dev() == seal.parent_device && parent_metadata.ino() == seal.parent_inode,
        "payload staging parent identity changed"
    );
    let directory = match fs::symlink_metadata(&seal.root) {
        Ok(metadata) => metadata,
        Err(error) if allow_removed && error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    ensure!(
        directory.is_dir()
            && directory.uid() == 0
            && directory.mode() & 0o7022 == 0
            && directory.dev() == seal.directory_device
            && directory.ino() == seal.directory_inode,
        "payload staging identity changed"
    );
    snapshot::require_path(&seal.root)
}

pub(super) fn verify(journal: &UpgradeJournal) -> anyhow::Result<()> {
    verify_payload(journal, false)
}

fn before_effects(journal: &UpgradeJournal) -> anyhow::Result<()> {
    ensure!(
        journal.phase == super::UpgradePhase::Prechecked
            && !journal.backup_complete
            && !journal.new_program_may_have_written
            && !journal.recovered_program_may_have_written,
        "partial staging authority is only valid before transaction effects"
    );
    Ok(())
}

pub(super) fn verify_precheck(journal: &UpgradeJournal) -> anyhow::Result<()> {
    before_effects(journal)?;
    verify_payload(journal, true)
}

pub(super) fn record_payload_stage(
    journal: &mut UpgradeJournal,
    directory: &Path,
    created: &fs::Metadata,
) -> anyhow::Result<()> {
    ensure!(
        journal.payload_stage_seal.is_none(),
        "payload staging is already recorded"
    );
    verify_work(journal)?;
    let parent = &journal.plan.work_directory;
    ensure!(
        directory == parent.join("target-payload"),
        "payload staging creation differs from operation"
    );
    let parent_metadata = private_metadata(parent)?;
    let metadata = private_metadata(directory)?;
    ensure!(
        metadata.dev() == created.dev() && metadata.ino() == created.ino(),
        "new payload staging identity changed"
    );
    journal.payload_stage_seal = Some(StageAuthority {
        root: directory.to_path_buf(),
        parent_device: parent_metadata.dev(),
        parent_inode: parent_metadata.ino(),
        directory_device: metadata.dev(),
        directory_inode: metadata.ino(),
    });
    super::save(journal)
}

pub(super) fn root(journal: &UpgradeJournal) -> anyhow::Result<PathBuf> {
    verify(journal)?;
    Ok(journal.plan.work_directory.clone())
}

/// Delete only the inode recorded for this operation's unpublished payload.
/// Unknown entries and replaced roots remain untouched.
fn cleanup_payload(journal: &UpgradeJournal) -> anyhow::Result<()> {
    verify_payload(journal, true)?;
    let Some(seal) = &journal.payload_stage_seal else {
        return Ok(());
    };
    if !snapshot::named_exists(&seal.root)? {
        return Ok(());
    }
    fn remove(path: &Path, depth: usize, inspected: &mut usize) -> anyhow::Result<()> {
        ensure!(
            depth <= 128 && *inspected < 8192,
            "staging cleanup exceeds entry bounds"
        );
        *inspected += 1;
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            (metadata.is_file() || metadata.is_dir())
                && metadata.uid() == 0
                && metadata.mode() & 0o7022 == 0
                && (!metadata.is_file() || metadata.nlink() == 1),
            "staging entry changed or is unsafe"
        );
        if metadata.is_dir() {
            let children = fs::read_dir(path)?
                .take(8193)
                .collect::<Result<Vec<_>, _>>()?;
            ensure!(
                children.len() <= 8192 - *inspected,
                "staging cleanup exceeds entry bounds"
            );
            for child in children {
                remove(&child.path(), depth + 1, inspected)?;
            }
            let after = fs::symlink_metadata(path)?;
            ensure!(
                after.dev() == metadata.dev() && after.ino() == metadata.ino(),
                "staging directory was replaced"
            );
            fs::remove_dir(path)?;
        } else {
            let after = snapshot::open_regular(path)?.metadata()?;
            ensure!(
                after.dev() == metadata.dev() && after.ino() == metadata.ino(),
                "staging file was replaced"
            );
            fs::remove_file(path)?;
        }
        snapshot::sync_parent(path)
    }
    remove(&seal.root, 0, &mut 0)
}

pub(super) fn cleanup_precheck(journal: &UpgradeJournal) -> anyhow::Result<()> {
    before_effects(journal)?;
    cleanup_payload(journal)
}

pub(super) fn cleanup_completed(journal: &UpgradeJournal) -> anyhow::Result<()> {
    ensure!(
        matches!(
            journal.phase,
            super::UpgradePhase::Ready | super::UpgradePhase::RolledBack
        ),
        "completed staging cleanup requires a closed upgrade"
    );
    cleanup_payload(journal)
}

/// Read assigned addresses without contacting another host or changing a socket.
#[allow(unsafe_code)] // libc owns the getifaddrs list until freeifaddrs below.
pub(super) fn local_ip_addresses() -> anyhow::Result<Vec<std::net::IpAddr>> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    let mut head = std::ptr::null_mut();
    // SAFETY: head is a valid output pointer. A successful call owns one list.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("cannot inspect local readiness addresses");
    }
    let mut addresses = Vec::new();
    let mut current = head;
    // SAFETY: every node/address belongs to the successful getifaddrs result.
    // Check the family before casting; copy only value fields and free once.
    unsafe {
        while !current.is_null() {
            let node = &*current;
            if !node.ifa_addr.is_null() {
                match i32::from((*node.ifa_addr).sa_family) {
                    libc::AF_INET => {
                        let address = &*node.ifa_addr.cast::<libc::sockaddr_in>();
                        addresses.push(IpAddr::V4(Ipv4Addr::from(
                            address.sin_addr.s_addr.to_ne_bytes(),
                        )));
                    }
                    libc::AF_INET6 => {
                        let address = &*node.ifa_addr.cast::<libc::sockaddr_in6>();
                        addresses.push(IpAddr::V6(Ipv6Addr::from(address.sin6_addr.s6_addr)));
                    }
                    _ => {}
                }
            }
            current = node.ifa_next;
        }
        libc::freeifaddrs(head);
    }
    Ok(addresses)
}
