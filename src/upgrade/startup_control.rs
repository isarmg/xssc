//! Durable OS startup control. Product runtimes never read these records.
use super::{UpgradeJournal, UpgradePhase, execution, snapshot};
use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

const UNIT_ROOT: &str = "/etc/systemd/system";
const MAX_DROP_INS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Status {
    Installing,
    Installed,
    Releasing,
    Released,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum FileStatus {
    Reserved,
    Written,
    Removing,
    Removed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UnitAuthority {
    service: String,
    directory: PathBuf,
    parent_device: u64,
    parent_inode: u64,
    directory_device: Option<u64>,
    directory_inode: Option<u64>,
    file_device: Option<u64>,
    file_inode: Option<u64>,
    status: FileStatus,
    original: Observation,
    current: Observation,
    stop_requested_at_micros: Option<u64>,
    stop_attempts: u32,
    stopped_at_micros: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    observed_at_micros: u64,
    load_state: String,
    unit_file_state: String,
    active_state: String,
    sub_state: String,
    main_pid: u32,
    control_pid: u32,
    job_pending: bool,
    control_group: String,
    cgroup_populated: bool,
}

impl Observation {
    fn stopped(&self) -> bool {
        self.load_state == "loaded"
            && matches!(self.active_state.as_str(), "inactive" | "failed")
            && matches!(self.sub_state.as_str(), "dead" | "failed")
            && self.main_pid == 0
            && self.control_pid == 0
            && !self.job_pending
            && !self.cgroup_populated
    }
}

fn now_micros() -> anyhow::Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_micros()
        .try_into()?)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Authority {
    operation_id: uuid::Uuid,
    permit: PathBuf,
    status: Status,
    units: Vec<UnitAuthority>,
}

trait Manager {
    fn reload(&mut self) -> anyhow::Result<()>;
    fn inspect(
        &mut self,
        service: &str,
        previous_group: Option<&str>,
    ) -> anyhow::Result<Observation>;
    fn stop(&mut self, service: &str) -> anyhow::Result<()>;
    fn observes(
        &mut self,
        service: &str,
        file: &Path,
        permit: &Path,
        present: bool,
    ) -> anyhow::Result<()>;
}

struct Systemd {
    timeout: u64,
}
impl Systemd {
    fn bus(&self, args: &[String]) -> anyhow::Result<serde_json::Value> {
        let mut options = vec![
            "--system".into(),
            "--json=short".into(),
            "--auto-start=no".into(),
            "--allow-interactive-authorization=no".into(),
        ];
        options.extend_from_slice(args);
        Ok(serde_json::from_slice(&super::run_bounded(
            "/usr/bin/busctl",
            &options,
            self.timeout,
        )?)?)
    }
    fn property(&self, object: &str, property: &str) -> anyhow::Result<serde_json::Value> {
        let value = self.bus(&[
            "get-property".into(),
            "org.freedesktop.systemd1".into(),
            object.into(),
            "org.freedesktop.systemd1.Unit".into(),
            property.into(),
        ])?;
        value
            .get("data")
            .cloned()
            .context("manager property data missing")
    }
}
impl Manager for Systemd {
    fn inspect(
        &mut self,
        service: &str,
        previous_group: Option<&str>,
    ) -> anyhow::Result<Observation> {
        let bytes = super::run_bounded(
            "/usr/bin/systemctl",
            &[
                "show".into(),
                service.into(),
                "--property=LoadState,UnitFileState,ActiveState,SubState,MainPID,ControlPID,Job,ControlGroup".into(),
            ],
            self.timeout,
        )?;
        observation(&bytes, previous_group, Path::new("/sys/fs/cgroup"))
    }
    fn stop(&mut self, service: &str) -> anyhow::Result<()> {
        super::run_bounded(
            "/usr/bin/systemctl",
            &["stop".into(), service.into()],
            self.timeout,
        )?;
        Ok(())
    }
    fn reload(&mut self) -> anyhow::Result<()> {
        super::run_bounded(
            "/usr/bin/systemctl",
            &["daemon-reload".into()],
            self.timeout,
        )?;
        Ok(())
    }
    fn observes(
        &mut self,
        service: &str,
        file: &Path,
        permit: &Path,
        present: bool,
    ) -> anyhow::Result<()> {
        let reply = self.bus(&[
            "call".into(),
            "org.freedesktop.systemd1".into(),
            "/org/freedesktop/systemd1".into(),
            "org.freedesktop.systemd1.Manager".into(),
            "GetUnit".into(),
            "s".into(),
            service.into(),
        ])?;
        ensure!(reply["type"] == "o", "manager did not identify a unit");
        let object = reply["data"]
            .as_array()
            .and_then(|v| v.first())
            .and_then(serde_json::Value::as_str)
            .context("manager unit object missing")?;
        ensure!(
            object.starts_with("/org/freedesktop/systemd1/unit/"),
            "unexpected manager object"
        );
        let drop_ins = self.property(object, "DropInPaths")?;
        let loaded = self.property(object, "LoadState")?;
        // Scalar properties use a JSON string in the actual busctl reply.
        ensure!(
            loaded.as_str() == Some("loaded"),
            "writer unit is not loaded"
        );
        let paths = drop_ins
            .as_array()
            .context("manager drop-in list missing")?;
        ensure!(
            paths.iter().any(|p| p.as_str() == file.to_str()) == present,
            "manager drop-in authority differs"
        );
        let conditions = self.property(object, "Conditions")?;
        let conditions = conditions
            .as_array()
            .context("manager conditions missing")?;
        let matched = conditions.iter().any(|condition| {
            condition.as_array().is_some_and(|parts| {
                parts.len() == 5
                    && parts[0] == "ConditionPathExists"
                    && parts[1] == false
                    && parts[2] == false
                    && parts[3].as_str() == permit.to_str()
            })
        });
        ensure!(matched == present, "manager startup condition differs");
        Ok(())
    }
}

fn cgroup_populated(root: &Path, group: &str) -> anyhow::Result<bool> {
    if group.is_empty() {
        return Ok(false);
    }
    let path = Path::new(group);
    ensure!(
        path.is_absolute()
            && path.components().all(|part| matches!(
                part,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            ))
            && !group.chars().any(char::is_control)
            && group.len() <= 4096,
        "manager control group is invalid"
    );
    // cgroup.events reports descendants as well as the service's direct tasks.
    // A stopped unit's group may already have been removed by the manager.
    let file = root.join(path.strip_prefix("/")?).join("cgroup.events");
    let mut source = match OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(&file)
    {
        Ok(source) => source,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            ensure!(
                root.join("cgroup.controllers").is_file(),
                "unified cgroup control is unavailable"
            );
            return Ok(false);
        }
        Err(error) => return Err(error.into()),
    };
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut source)
        .take(4097)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 4096, "control group status exceeds bound");
    let text = std::str::from_utf8(&bytes)?;
    let entries: Vec<_> = text
        .lines()
        .filter_map(|line| line.strip_prefix("populated "))
        .collect();
    ensure!(
        entries.len() == 1 && matches!(entries[0], "0" | "1"),
        "control group status is unknown"
    );
    Ok(entries[0] == "1")
}

fn observation(
    bytes: &[u8],
    previous_group: Option<&str>,
    cgroup_root: &Path,
) -> anyhow::Result<Observation> {
    let text = std::str::from_utf8(bytes)?;
    ensure!(text.len() <= 64 * 1024, "writer status exceeds bound");
    let mut properties = std::collections::BTreeMap::new();
    for line in text.lines() {
        let (name, value) = line
            .split_once('=')
            .context("writer property is malformed")?;
        ensure!(
            properties.insert(name, value).is_none(),
            "writer property is duplicated"
        );
    }
    ensure!(properties.len() == 8, "writer properties are incomplete");
    let get = |name| {
        properties
            .get(name)
            .copied()
            .context("writer property is missing")
    };
    let state = |name| -> anyhow::Result<String> {
        let value = get(name)?;
        ensure!(
            value.len() <= 128
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)),
            "writer state is invalid"
        );
        Ok(value.to_owned())
    };
    let control_group = get("ControlGroup")?.to_owned();
    let current_populated = cgroup_populated(cgroup_root, &control_group)?;
    let previous_populated = previous_group
        .filter(|group| *group != control_group)
        .map(|group| cgroup_populated(cgroup_root, group))
        .transpose()?
        .unwrap_or(false);
    let job = get("Job")?;
    // systemctl renders the default (0, "/") D-Bus job as the empty value.
    ensure!(
        job.len() <= 128 && !job.chars().any(char::is_control),
        "writer job is invalid"
    );
    let value = Observation {
        observed_at_micros: now_micros()?,
        load_state: state("LoadState")?,
        unit_file_state: state("UnitFileState")?,
        active_state: state("ActiveState")?,
        sub_state: state("SubState")?,
        main_pid: get("MainPID")?.parse()?,
        control_pid: get("ControlPID")?.parse()?,
        job_pending: !job.is_empty(),
        control_group,
        cgroup_populated: current_populated || previous_populated,
    };
    ensure!(
        value.load_state == "loaded",
        "writer unit is unknown or not loaded"
    );
    Ok(value)
}

fn services(journal: &UpgradeJournal) -> anyhow::Result<Vec<String>> {
    let mut names = vec![journal.plan.service.clone()];
    names.extend(
        journal
            .plan
            .additional_services
            .iter()
            .map(|v| v.service.clone()),
    );
    names.sort();
    ensure!(
        !names.is_empty() && names.len() <= 16 && names.windows(2).all(|v| v[0] != v[1]),
        "writer services must be unique and bounded"
    );
    for name in &names {
        ensure!(
            name.len() <= 128
                && name.ends_with(".service")
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
            "writer service name is invalid"
        );
    }
    Ok(names)
}

fn directory(path: &Path) -> anyhow::Result<fs::Metadata> {
    execution::require_trusted(path)?;
    let value = fs::symlink_metadata(path)?;
    ensure!(
        value.is_dir() && value.uid() == 0 && value.mode() & 0o7022 == 0,
        "unit configuration directory must be administrator controlled"
    );
    Ok(value)
}

fn file_path(unit: &UnitAuthority, operation: uuid::Uuid) -> PathBuf {
    unit.directory.join(format!("90-xssc-{operation}.conf"))
}

fn contents(permit: &Path) -> anyhow::Result<Vec<u8>> {
    let value = permit.to_str().context("startup condition must be UTF-8")?;
    ensure!(
        !value.chars().any(char::is_control),
        "startup condition contains control text"
    );
    // ConditionPathExists is a literal path value. Quotes and C escapes are
    // path characters here; only systemd specifiers need escaping.
    let literal = value.replace('%', "%%");
    Ok(format!("[Unit]\nConditionPathExists={literal}\n").into_bytes())
}

fn persist(journal: &mut UpgradeJournal, authority: &Authority) -> anyhow::Result<()> {
    journal.startup_control = Some(authority.clone());
    super::save(journal)
}

fn mapped(journal: &UpgradeJournal, authority: &Authority, unit_root: &Path) -> anyhow::Result<()> {
    execution::verify_work(journal)?;
    ensure!(
        authority.operation_id == journal.operation_id
            && authority.permit == journal.plan.work_directory.join("start-permit")
            && authority
                .units
                .iter()
                .map(|u| u.service.clone())
                .collect::<Vec<_>>()
                == services(journal)?,
        "startup control scope differs from the operation"
    );
    ensure!(
        !snapshot::named_exists(&authority.permit)?,
        "unexpected startup permit; no writes authorized"
    );
    for unit in &authority.units {
        ensure!(
            unit.directory == unit_root.join(format!("{}.d", unit.service)),
            "startup control directory mapping differs"
        );
        let parent = directory(unit_root)?;
        ensure!(
            parent.dev() == unit.parent_device && parent.ino() == unit.parent_inode,
            "unit configuration parent changed"
        );
        ensure!(
            unit.directory_device.is_some() == unit.directory_inode.is_some()
                && unit.file_device.is_some() == unit.file_inode.is_some(),
            "startup authority has incomplete identity"
        );
        if let (Some(device), Some(inode)) = (unit.directory_device, unit.directory_inode) {
            let dir = directory(&unit.directory)?;
            ensure!(
                dir.dev() == device && dir.ino() == inode,
                "unit drop-in directory changed"
            );
        }
    }
    Ok(())
}

fn open_guard(unit: &UnitAuthority, operation: uuid::Uuid) -> anyhow::Result<(File, Vec<u8>)> {
    let path = file_path(unit, operation);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(&path)?;
    let metadata = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == 0
            && metadata.nlink() == 1
            && matches!(metadata.mode() & 0o7777, 0o600 | 0o644)
            && metadata.len() <= 64 * 1024
            && Some(metadata.dev()) == unit.file_device
            && Some(metadata.ino()) == unit.file_inode
            && metadata.dev() == named.dev()
            && metadata.ino() == named.ino(),
        "startup control file identity changed"
    );
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 64 * 1024, "startup control exceeds bound");
    Ok((file, bytes))
}

fn reject_other_guards(unit: &UnitAuthority, operation: uuid::Uuid) -> anyhow::Result<()> {
    let entries = fs::read_dir(&unit.directory)?
        .take(MAX_DROP_INS + 1)
        .collect::<Result<Vec<_>, _>>()?;
    ensure!(
        entries.len() <= MAX_DROP_INS,
        "unit drop-in count exceeds bound"
    );
    let own = file_path(unit, operation);
    for entry in entries {
        if entry
            .file_name()
            .to_str()
            .is_some_and(|n| n.starts_with("90-xssc-") && n.ends_with(".conf"))
        {
            ensure!(
                entry.path() == own,
                "another upgrade controls this writer; recover it first"
            );
        }
    }
    Ok(())
}

fn establish_with(
    journal: &mut UpgradeJournal,
    unit_root: &Path,
    manager: &mut impl Manager,
) -> anyhow::Result<()> {
    execution::verify_work(journal)?;
    let mut authority = if let Some(authority) = &journal.startup_control {
        authority.clone()
    } else {
        let parent = directory(unit_root)?;
        let mut units = Vec::new();
        for service in services(journal)? {
            // Capture every writer before changing any system service setting.
            // A resumed operation keeps this original observation intact.
            let original = manager.inspect(&service, None)?;
            units.push(UnitAuthority {
                directory: unit_root.join(format!("{service}.d")),
                service,
                parent_device: parent.dev(),
                parent_inode: parent.ino(),
                directory_device: None,
                directory_inode: None,
                file_device: None,
                file_inode: None,
                status: FileStatus::Reserved,
                current: original.clone(),
                original,
                stop_requested_at_micros: None,
                stop_attempts: 0,
                stopped_at_micros: None,
            });
        }
        let value = Authority {
            operation_id: journal.operation_id,
            permit: journal.plan.work_directory.join("start-permit"),
            status: Status::Installing,
            units,
        };
        persist(journal, &value)?;
        value
    };
    mapped(journal, &authority, unit_root)?;
    if matches!(authority.status, Status::Released | Status::Releasing) {
        // A recovery first reinstates startup control before asking any writer
        // to stop. Removed files get new creation authority, never an old seal.
        for unit in &mut authority.units {
            if matches!(unit.status, FileStatus::Removed | FileStatus::Removing)
                && !snapshot::named_exists(&file_path(unit, authority.operation_id))?
            {
                ensure!(
                    !snapshot::named_exists(&file_path(unit, authority.operation_id))?,
                    "unowned startup control file appeared after release"
                );
                unit.file_device = None;
                unit.file_inode = None;
                unit.status = FileStatus::Reserved;
            } else if unit.status == FileStatus::Removing {
                let (_, bytes) = open_guard(unit, authority.operation_id)?;
                ensure!(
                    bytes == contents(&authority.permit)?,
                    "interrupted guard removal content changed"
                );
                unit.status = FileStatus::Written;
            }
        }
        authority.status = Status::Installing;
        persist(journal, &authority)?;
    }
    let expected = contents(&authority.permit)?;
    for index in 0..authority.units.len() {
        let unit = &authority.units[index];
        if unit.directory_device.is_none() {
            if !snapshot::named_exists(&unit.directory)? {
                fs::DirBuilder::new().mode(0o755).create(&unit.directory)?;
                snapshot::sync_parent(&unit.directory)?;
            }
            let metadata = directory(&unit.directory)?;
            authority.units[index].directory_device = Some(metadata.dev());
            authority.units[index].directory_inode = Some(metadata.ino());
            persist(journal, &authority)?;
        }
        mapped(journal, &authority, unit_root)?;
        reject_other_guards(&authority.units[index], authority.operation_id)?;
        if authority.units[index].file_device.is_none() {
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
                .open(file_path(&authority.units[index], authority.operation_id))?;
            let metadata = file.metadata()?;
            authority.units[index].file_device = Some(metadata.dev());
            authority.units[index].file_inode = Some(metadata.ino());
            persist(journal, &authority)?;
            file.sync_all()?;
        }
        let unit = &authority.units[index];
        let (mut file, actual) = open_guard(unit, authority.operation_id)?;
        if unit.status == FileStatus::Written {
            ensure!(
                actual == expected && file.metadata()?.mode() & 0o7777 == 0o644,
                "startup condition content changed"
            );
        } else {
            ensure!(
                unit.status == FileStatus::Reserved && expected.starts_with(&actual),
                "unrecognized startup condition contents"
            );
            file.set_len(0)?;
            // Reopen avoids relying on the reader cursor after a resumed write.
            drop(file);
            file = OpenOptions::new()
                .write(true)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
                .open(file_path(unit, authority.operation_id))?;
            ensure!(
                Some(file.metadata()?.ino()) == unit.file_inode
                    && Some(file.metadata()?.dev()) == unit.file_device,
                "startup condition was replaced before writing"
            );
            file.write_all(&expected)?;
            file.set_permissions(fs::Permissions::from_mode(0o644))?;
            file.sync_all()?;
            snapshot::sync_parent(&file_path(unit, authority.operation_id))?;
            authority.units[index].status = FileStatus::Written;
            persist(journal, &authority)?;
        }
    }
    manager.reload()?;
    authority.status = Status::Installed;
    persist(journal, &authority)?;
    verify_with(journal, unit_root, manager)
}

fn verify_with(
    journal: &UpgradeJournal,
    unit_root: &Path,
    manager: &mut impl Manager,
) -> anyhow::Result<()> {
    let authority = journal
        .startup_control
        .as_ref()
        .context("OS startup control missing")?;
    mapped(journal, authority, unit_root)?;
    ensure!(
        authority.status == Status::Installed,
        "OS startup control is not installed"
    );
    let expected = contents(&authority.permit)?;
    for unit in &authority.units {
        ensure!(
            unit.status == FileStatus::Written,
            "writer startup condition is incomplete"
        );
        let (file, bytes) = open_guard(unit, authority.operation_id)?;
        ensure!(
            bytes == expected && file.metadata()?.mode() & 0o7777 == 0o644,
            "writer startup condition changed"
        );
        reject_other_guards(unit, authority.operation_id)?;
        manager.observes(
            &unit.service,
            &file_path(unit, authority.operation_id),
            &authority.permit,
            true,
        )?;
    }
    Ok(())
}

fn release_with(
    journal: &mut UpgradeJournal,
    unit_root: &Path,
    manager: &mut impl Manager,
) -> anyhow::Result<()> {
    ensure!(
        matches!(
            journal.phase,
            UpgradePhase::StartIntent | UpgradePhase::RecoveryStartIntent
        ),
        "startup release requires a persisted start intent"
    );
    let mut authority = journal
        .startup_control
        .clone()
        .context("OS startup control missing")?;
    mapped(journal, &authority, unit_root)?;
    ensure!(
        matches!(
            authority.status,
            Status::Installed | Status::Releasing | Status::Released
        ),
        "incomplete OS startup control cannot be released"
    );
    authority.status = Status::Releasing;
    persist(journal, &authority)?;
    let expected = contents(&authority.permit)?;
    for index in 0..authority.units.len() {
        let unit = &authority.units[index];
        let path = file_path(unit, authority.operation_id);
        if snapshot::named_exists(&path)? {
            let (_, bytes) = open_guard(unit, authority.operation_id)?;
            ensure!(
                bytes == expected && unit.status != FileStatus::Removed,
                "startup release refuses a changed condition"
            );
            authority.units[index].status = FileStatus::Removing;
            persist(journal, &authority)?;
            open_guard(&authority.units[index], authority.operation_id)?;
            fs::remove_file(&path)?;
            snapshot::sync_parent(&path)?;
        } else {
            ensure!(
                matches!(unit.status, FileStatus::Removing | FileStatus::Removed),
                "startup condition disappeared without removal intent"
            );
        }
        authority.units[index].status = FileStatus::Removed;
        persist(journal, &authority)?;
    }
    manager.reload()?;
    for unit in &authority.units {
        manager.observes(
            &unit.service,
            &file_path(unit, authority.operation_id),
            &authority.permit,
            false,
        )?;
    }
    authority.status = Status::Released;
    persist(journal, &authority)
}

pub(super) fn establish(journal: &mut UpgradeJournal) -> anyhow::Result<()> {
    let timeout = journal.plan.timeout_seconds;
    establish_with(journal, Path::new(UNIT_ROOT), &mut Systemd { timeout })
}
pub(super) fn verify(journal: &UpgradeJournal) -> anyhow::Result<()> {
    verify_with(
        journal,
        Path::new(UNIT_ROOT),
        &mut Systemd {
            timeout: journal.plan.timeout_seconds,
        },
    )
}
pub(super) fn release(journal: &mut UpgradeJournal) -> anyhow::Result<()> {
    let timeout = journal.plan.timeout_seconds;
    release_with(journal, Path::new(UNIT_ROOT), &mut Systemd { timeout })
}

fn stop_with(
    journal: &mut UpgradeJournal,
    unit_root: &Path,
    manager: &mut impl Manager,
) -> anyhow::Result<()> {
    verify_with(journal, unit_root, manager)?;
    let mut authority = journal
        .startup_control
        .clone()
        .context("OS startup control missing")?;
    let order = std::iter::once(journal.plan.service.clone())
        .chain(
            journal
                .plan
                .additional_services
                .iter()
                .rev()
                .map(|entry| entry.service.clone()),
        )
        .collect::<Vec<_>>();
    for service in order {
        let index = authority
            .units
            .iter()
            .position(|unit| unit.service == service)
            .context("writer has no durable authority")?;
        let before = manager.inspect(
            &service,
            Some(&authority.units[index].original.control_group),
        )?;
        authority.units[index].current = before.clone();
        authority.units[index].stopped_at_micros = None;
        persist(journal, &authority)?;
        if !before.stopped() {
            authority.units[index].stop_requested_at_micros = Some(now_micros()?);
            authority.units[index].stop_attempts = authority.units[index]
                .stop_attempts
                .checked_add(1)
                .context("writer stop attempt counter exceeded its bound")?;
            persist(journal, &authority)?;
            let stopped = manager.stop(&service);
            // Persist the actual result even if the manager command failed or
            // its completion was unknown. An interrupted intent is retryable.
            let current = manager.inspect(&service, Some(&before.control_group))?;
            authority.units[index].current = current;
            persist(journal, &authority)?;
            stopped?;
        }
        ensure!(
            authority.units[index].current.stopped(),
            "writer did not actually exit"
        );
        authority.units[index].stopped_at_micros =
            Some(authority.units[index].current.observed_at_micros);
        persist(journal, &authority)?;
    }
    // Recheck the whole group: a successful stop of a later dependency cannot
    // substitute for proof that an earlier writer remains stopped.
    for index in 0..authority.units.len() {
        let unit = &authority.units[index];
        let current = manager.inspect(&unit.service, Some(&unit.original.control_group))?;
        authority.units[index].current = current;
        persist(journal, &authority)?;
        ensure!(
            authority.units[index].current.stopped(),
            "writer restarted during maintenance acquisition"
        );
    }
    verify_with(journal, unit_root, manager)
}

pub(super) fn stop(journal: &mut UpgradeJournal) -> anyhow::Result<()> {
    let timeout = journal.plan.timeout_seconds;
    stop_with(journal, Path::new(UNIT_ROOT), &mut Systemd { timeout })
}

/// Failure recovery restores the captured startup state. A normal upgrade
/// deliberately starts the target; recovery does not start previously stopped
/// or already stopping writers merely because an upgrade was attempted.
pub(super) fn original_required_services(journal: &UpgradeJournal) -> anyhow::Result<Vec<String>> {
    let authority = journal
        .startup_control
        .as_ref()
        .context("original writer state is missing")?;
    let mut result = Vec::new();
    for service in journal
        .plan
        .additional_services
        .iter()
        .map(|entry| &entry.service)
        .chain(std::iter::once(&journal.plan.service))
    {
        let unit = authority
            .units
            .iter()
            .find(|unit| &unit.service == service)
            .context("original writer has no authority")?;
        ensure!(
            unit.original.load_state == "loaded",
            "original writer was not loaded"
        );
        if matches!(
            unit.original.active_state.as_str(),
            "active" | "activating" | "reloading"
        ) {
            result.push(service.clone());
        }
    }
    Ok(result)
}

/// A completed record cannot be collected while it owns an OS startup guard.
/// This check is read-only and does not contact or alter the service manager.
pub(super) fn collection_ready(journal: &UpgradeJournal) -> anyhow::Result<()> {
    execution::verify_work(journal)?;
    ensure!(
        !snapshot::named_exists(&journal.plan.work_directory.join("start-permit"))?,
        "unknown startup permit must be retained"
    );
    if let Some(authority) = &journal.startup_control {
        mapped(journal, authority, Path::new(UNIT_ROOT))?;
        ensure!(
            authority.status == Status::Released
                && authority
                    .units
                    .iter()
                    .all(|unit| unit.status == FileStatus::Removed),
            "startup control is still held"
        );
        for unit in &authority.units {
            ensure!(
                !snapshot::named_exists(&file_path(unit, authority.operation_id))?,
                "released startup guard was recreated"
            );
        }
    } else {
        for service in services(journal)? {
            let path = Path::new(UNIT_ROOT)
                .join(format!("{service}.d"))
                .join(format!("90-xssc-{}.conf", journal.operation_id));
            ensure!(
                !snapshot::named_exists(&path)?,
                "unrecorded startup guard must be retained"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Default)]
    struct ObservedManager {
        reloads: usize,
        reject: bool,
        writers: Vec<(String, bool)>,
        states: std::collections::BTreeMap<String, Observation>,
        stops: Vec<String>,
        keep_writer: bool,
    }
    impl Manager for ObservedManager {
        fn inspect(
            &mut self,
            service: &str,
            _previous_group: Option<&str>,
        ) -> anyhow::Result<Observation> {
            let mut value = self
                .states
                .get(service)
                .cloned()
                .unwrap_or_else(stopped_observation);
            value.observed_at_micros = now_micros()?;
            Ok(value)
        }
        fn stop(&mut self, service: &str) -> anyhow::Result<()> {
            self.stops.push(service.to_owned());
            if !self.keep_writer {
                self.states
                    .insert(service.to_owned(), stopped_observation());
            }
            Ok(())
        }
        fn reload(&mut self) -> anyhow::Result<()> {
            self.reloads += 1;
            Ok(())
        }
        fn observes(
            &mut self,
            service: &str,
            file: &Path,
            permit: &Path,
            present: bool,
        ) -> anyhow::Result<()> {
            ensure!(!self.reject, "fixture manager rejected effective condition");
            ensure!(
                file.exists() == present && !permit.exists(),
                "fixture authority differs"
            );
            if present {
                ensure!(
                    fs::read(file)? == contents(permit)?,
                    "fixture condition differs"
                );
            }
            self.writers.push((service.to_owned(), present));
            Ok(())
        }
    }
    fn stopped_observation() -> Observation {
        Observation {
            observed_at_micros: 1,
            load_state: "loaded".into(),
            unit_file_state: "disabled".into(),
            active_state: "inactive".into(),
            sub_state: "dead".into(),
            main_pid: 0,
            control_pid: 0,
            job_pending: false,
            control_group: String::new(),
            cgroup_populated: false,
        }
    }
    fn fixture() -> (tempfile::TempDir, UpgradeJournal, PathBuf) {
        let (root, journal) = super::super::tests::startup_fixture();
        let units = root.path().join("unit-definitions");
        fs::DirBuilder::new().mode(0o755).create(&units).unwrap();
        (root, journal, units)
    }
    #[test]
    fn all_writers_are_controlled_until_persisted_start_intent() {
        let (_root, mut journal, units) = fixture();
        let mut manager = ObservedManager::default();
        establish_with(&mut journal, &units, &mut manager).unwrap();
        assert_eq!(manager.reloads, 1);
        assert_eq!(manager.writers.len(), 2);
        assert!(manager.writers.iter().all(|(_, present)| *present));
        assert!(release_with(&mut journal, &units, &mut manager).is_err());
        journal.phase = UpgradePhase::StartIntent;
        super::super::save(&journal).unwrap();
        release_with(&mut journal, &units, &mut manager).unwrap();
        assert_eq!(
            journal.startup_control.as_ref().unwrap().status,
            Status::Released
        );
        assert!(
            manager
                .writers
                .iter()
                .rev()
                .take(2)
                .all(|(_, present)| !present)
        );
        journal.phase = UpgradePhase::RecoveryMaintenanceIntent;
        super::super::save(&journal).unwrap();
        establish_with(&mut journal, &units, &mut manager).unwrap();
        verify_with(&journal, &units, &mut manager).unwrap();
    }
    #[test]
    fn changed_inode_or_condition_is_retained_and_refuses_release() {
        for replace in [false, true] {
            let (_root, mut journal, units) = fixture();
            let mut manager = ObservedManager::default();
            establish_with(&mut journal, &units, &mut manager).unwrap();
            let authority = journal.startup_control.as_ref().unwrap();
            let path = file_path(&authority.units[0], authority.operation_id);
            if replace {
                fs::rename(&path, path.with_extension("evidence")).unwrap();
                fs::write(&path, contents(&authority.permit).unwrap()).unwrap();
            } else {
                fs::write(&path, b"[Unit]\nConditionPathExists=/changed\n").unwrap();
            }
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            let evidence = fs::read(&path).unwrap();
            assert!(verify_with(&journal, &units, &mut manager).is_err());
            journal.phase = UpgradePhase::StartIntent;
            super::super::save(&journal).unwrap();
            assert!(release_with(&mut journal, &units, &mut manager).is_err());
            assert_eq!(fs::read(path).unwrap(), evidence);
        }
    }
    #[test]
    fn manager_rejection_or_unexpected_permit_refuses_writes() {
        let (_root, mut journal, units) = fixture();
        let mut manager = ObservedManager {
            reject: true,
            ..Default::default()
        };
        assert!(establish_with(&mut journal, &units, &mut manager).is_err());
        manager.reject = false;
        establish_with(&mut journal, &units, &mut manager).unwrap();
        let permit = journal.startup_control.as_ref().unwrap().permit.clone();
        fs::write(&permit, b"unknown operator object").unwrap();
        assert!(verify_with(&journal, &units, &mut manager).is_err());
        assert_eq!(fs::read(permit).unwrap(), b"unknown operator object");
    }
    #[test]
    fn release_resume_retains_unrelated_drop_ins() {
        let (_root, mut journal, units) = fixture();
        let mut manager = ObservedManager::default();
        establish_with(&mut journal, &units, &mut manager).unwrap();
        let authority = journal.startup_control.as_mut().unwrap();
        let unit = &mut authority.units[0];
        let unrelated = unit.directory.join("operator.conf");
        fs::write(&unrelated, b"[Unit]\nDescription=operator configuration\n").unwrap();
        fs::set_permissions(&unrelated, fs::Permissions::from_mode(0o644)).unwrap();
        let path = file_path(unit, authority.operation_id);
        unit.status = FileStatus::Removing;
        authority.status = Status::Releasing;
        journal.phase = UpgradePhase::StartIntent;
        super::super::save(&journal).unwrap();
        fs::remove_file(path).unwrap();
        release_with(&mut journal, &units, &mut manager).unwrap();
        assert_eq!(
            fs::read(unrelated).unwrap(),
            b"[Unit]\nDescription=operator configuration\n"
        );
    }
    #[test]
    fn foreign_upgrade_guard_is_retained() {
        let (_root, mut journal, units) = fixture();
        let mut manager = ObservedManager::default();
        let service = services(&journal).unwrap().remove(0);
        let drop_ins = units.join(format!("{service}.d"));
        fs::DirBuilder::new().mode(0o755).create(&drop_ins).unwrap();
        let unknown = drop_ins.join("90-xssc-00000000-0000-4000-8000-000000000000.conf");
        fs::write(&unknown, b"[Unit]\nConditionPathExists=/unknown\n").unwrap();
        assert!(establish_with(&mut journal, &units, &mut manager).is_err());
        assert_eq!(
            fs::read(unknown).unwrap(),
            b"[Unit]\nConditionPathExists=/unknown\n"
        );
    }
    #[test]
    fn condition_path_preserves_literal_special_characters() {
        let permit = Path::new("/tmp/root with space/quote\"slash\\and%percent/start-permit");
        assert_eq!(
            String::from_utf8(contents(permit).unwrap()).unwrap(),
            "[Unit]\nConditionPathExists=/tmp/root with space/quote\"slash\\and%%percent/start-permit\n"
        );
    }

    #[test]
    fn original_writer_state_and_each_stop_result_survive_resume() {
        let (_root, mut journal, units) = fixture();
        let mut manager = ObservedManager::default();
        for service in services(&journal).unwrap() {
            let mut active = stopped_observation();
            active.active_state = "active".into();
            active.sub_state = "running".into();
            active.main_pid = 123;
            active.unit_file_state = "enabled".into();
            active.control_group = format!("/system.slice/{service}");
            active.cgroup_populated = true;
            manager.states.insert(service, active);
        }
        establish_with(&mut journal, &units, &mut manager).unwrap();
        manager.keep_writer = true;
        assert!(stop_with(&mut journal, &units, &mut manager).is_err());
        let interrupted: UpgradeJournal = serde_json::from_slice(
            &fs::read(journal.plan.work_directory.join(super::super::JOURNAL)).unwrap(),
        )
        .unwrap();
        let authority = interrupted.startup_control.as_ref().unwrap();
        let first = authority
            .units
            .iter()
            .find(|unit| unit.service == journal.plan.service)
            .unwrap();
        assert!(first.stop_requested_at_micros.is_some());
        assert_eq!(first.stop_attempts, 1);
        assert!(first.stopped_at_micros.is_none());
        assert_eq!(first.original.main_pid, 123);
        journal = interrupted;
        manager.keep_writer = false;
        stop_with(&mut journal, &units, &mut manager).unwrap();
        let authority = journal.startup_control.as_ref().unwrap();
        assert!(
            authority
                .units
                .iter()
                .all(|unit| unit.original.main_pid == 123
                    && unit.original.unit_file_state == "enabled"
                    && unit.current.stopped()
                    && unit.stopped_at_micros.is_some())
        );
        let calls = manager.stops.len();
        stop_with(&mut journal, &units, &mut manager).unwrap();
        assert_eq!(manager.stops.len(), calls);
    }

    #[test]
    fn recovery_keeps_previously_inactive_writers_stopped() {
        let (_root, mut journal, units) = fixture();
        let mut manager = ObservedManager::default();
        let secondary = journal.plan.additional_services[0].service.clone();
        let mut active = stopped_observation();
        active.active_state = "active".into();
        active.sub_state = "running".into();
        active.main_pid = 42;
        manager.states.insert(secondary.clone(), active);
        establish_with(&mut journal, &units, &mut manager).unwrap();
        stop_with(&mut journal, &units, &mut manager).unwrap();
        assert_eq!(original_required_services(&journal).unwrap(), [secondary]);
    }

    #[test]
    fn inactive_main_pid_is_insufficient_when_control_job_or_descendant_remains() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("cgroup.controllers"), b"cpu memory").unwrap();
        fs::create_dir(root.path().join("writer")).unwrap();
        let events = root.path().join("writer/cgroup.events");
        fs::write(&events, b"populated 1\nfrozen 0\n").unwrap();
        let base = "LoadState=loaded\nUnitFileState=disabled\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nJob=\nControlGroup=\n";
        assert!(
            observation(base.as_bytes(), None, root.path())
                .unwrap()
                .stopped()
        );
        assert!(
            !observation(base.as_bytes(), Some("/writer"), root.path())
                .unwrap()
                .stopped()
        );
        fs::write(&events, b"populated 0\nfrozen 0\n").unwrap();
        assert!(
            observation(base.as_bytes(), Some("/writer"), root.path())
                .unwrap()
                .stopped()
        );
        for changed in [
            base.replace("ControlPID=0", "ControlPID=41"),
            base.replace("Job=\n", "Job=9\n"),
            base.replace("ActiveState=inactive", "ActiveState=deactivating"),
            base.replace("LoadState=loaded", "LoadState=not-found"),
        ] {
            assert!(
                !observation(changed.as_bytes(), None, root.path())
                    .is_ok_and(|value| value.stopped())
            );
        }
        assert!(
            observation(
                base.replace("ControlGroup=\n", "ControlGroup=/../writer\n")
                    .as_bytes(),
                None,
                root.path()
            )
            .is_err()
        );
        fs::write(&events, b"populated 0\npopulated 0\n").unwrap();
        assert!(observation(base.as_bytes(), Some("/writer"), root.path()).is_err());
    }
}
