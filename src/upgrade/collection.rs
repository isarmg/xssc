//! Explicit retention of closed transactions; durable inode authority survives interruption.
use super::{ServiceControl, UpgradeJournal, UpgradePhase, execution, native_release, snapshot};
use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const MAX_ENTRIES: usize = 200_000;
const MAX_RECORD: u64 = 64 * 1024 * 1024;
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RetentionPolicy {
    pub minimum_age_seconds: u64,
    pub keep_completed: usize,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Object {
    path: PathBuf,
    device: u64,
    inode: u64,
    directory: bool,
    mode: u32,
    size: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Candidate {
    journal: UpgradeJournal,
    objects: Vec<Object>,
    removed: bool,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    operation_id: uuid::Uuid,
    root: PathBuf,
    parent_device: u64,
    parent_inode: u64,
    policy: RetentionPolicy,
    candidates: Vec<Candidate>,
    retired_records: Vec<RetiredRecord>,
    complete: bool,
    completed_at_micros: Option<u64>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RetiredRecord {
    path: PathBuf,
    device: u64,
    inode: u64,
    sha256: String,
    removed: bool,
}
#[derive(Serialize)]
struct Decision {
    work_directory: PathBuf,
    reason: &'static str,
}

fn now() -> anyhow::Result<u64> {
    Ok(u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_micros(),
    )?)
}
fn expired(journal: &UpgradeJournal, policy: &RetentionPolicy) -> anyhow::Result<bool> {
    let Some(completed) = journal.completed_at_micros else {
        return Ok(false);
    };
    Ok(now()?
        .checked_sub(completed)
        .is_some_and(|age| age / 1_000_000 >= policy.minimum_age_seconds))
}
fn entries(root: &Path) -> anyhow::Result<Vec<PathBuf>> {
    match fs::read_dir(root) {
        Ok(entries) => {
            let paths = entries
                .take(4097)
                .map(|entry| Ok(entry?.path()))
                .collect::<anyhow::Result<Vec<_>>>()?;
            ensure!(paths.len() <= 4096, "transaction list exceeds bound");
            Ok(paths)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error.into()),
    }
}
fn references(
    root: &Path,
    candidate: &Path,
    current_collection: Option<&Path>,
) -> anyhow::Result<bool> {
    fn points(value: &serde_json::Value, target: &Path) -> bool {
        match value {
            serde_json::Value::String(value) => {
                let path = Path::new(value);
                path.is_absolute() && path.starts_with(target)
            }
            serde_json::Value::Array(values) => values.iter().any(|value| points(value, target)),
            serde_json::Value::Object(values) => values.values().any(|value| points(value, target)),
            _ => false,
        }
    }
    for work in entries(&root.join("maintenance/upgrades"))? {
        if work == candidate {
            continue;
        }
        let path = work.join("upgrade.json");
        if !snapshot::named_exists(&path)? {
            continue;
        }
        // An unreadable/malformed declared transaction cannot prove lack of references.
        let value: serde_json::Value =
            serde_json::from_slice(&snapshot::read_bounded(&path, MAX_RECORD)?)?;
        if points(&value, candidate) {
            return Ok(true);
        }
    }
    for path in entries(&root.join("maintenance/collections"))? {
        if Some(path.as_path()) == current_collection {
            continue;
        }
        if path.extension() != Some(std::ffi::OsStr::new("json")) {
            continue;
        }
        let value: serde_json::Value =
            serde_json::from_slice(&snapshot::read_bounded(&path, MAX_RECORD)?)?;
        if value.get("complete") != Some(&serde_json::Value::Bool(true))
            && points(&value, candidate)
        {
            return Ok(true);
        }
    }
    Ok(false)
}
fn known_contents(journal: &UpgradeJournal) -> anyhow::Result<()> {
    let work = &journal.plan.work_directory;
    let mut allowed = BTreeSet::from([
        "upgrade.json".to_owned(),
        xcsc::state_file::MAINTENANCE_LOCK_FILE.to_owned(),
    ]);
    if journal.payload_stage_seal.is_some() {
        let backup = journal
            .native_backup
            .as_ref()
            .context("unrecorded target payload inventory")?;
        ensure!(
            snapshot::inventory(&work.join("target-payload"), true, u64::MAX, false)?
                == backup.target_entries,
            "target payload inventory differs"
        );
        allowed.insert("target-payload".into());
    }
    let work_lock = work.join(xcsc::state_file::MAINTENANCE_LOCK_FILE);
    if snapshot::named_exists(&work_lock)? {
        let info = fs::symlink_metadata(&work_lock)?;
        ensure!(
            info.is_file()
                && info.uid() == 0
                && info.mode() & 0o7777 == 0o600
                && info.nlink() == 1
                && info.len() == 0,
            "unknown maintenance lock content"
        );
    }
    if snapshot::named_exists(&work.join("original-binary"))? {
        ensure!(
            snapshot::digest_file(&work.join("original-binary"))? == journal.original_binary_sha256,
            "original backup differs"
        );
        allowed.insert("original-binary".into());
    }
    if snapshot::named_exists(&work.join("original-payload"))? {
        let backup = journal
            .native_backup
            .as_ref()
            .context("unrecorded original payload")?;
        ensure!(
            snapshot::inventory(&work.join("original-payload"), true, u64::MAX, false)?
                == backup.source_entries,
            "original payload backup differs"
        );
        allowed.insert("original-payload".into());
    }
    for (index, backup) in journal.backups.iter().enumerate() {
        let name = format!("resource-{index}");
        let path = work.join(&name);
        ensure!(
            super::resource_inventory(journal, &backup.resource, &path, false)? == backup.entries,
            "resource backup differs"
        );
        allowed.insert(name);
    }
    for path in entries(work)? {
        ensure!(
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| allowed.contains(name)),
            "unknown transaction content must be preserved"
        );
    }
    super::startup_control::collection_ready(journal)?;
    execution::verify_work(journal)
}
fn capture(work: &Path) -> anyhow::Result<Vec<Object>> {
    fn visit(
        root: &Path,
        path: &Path,
        objects: &mut Vec<Object>,
        depth: usize,
    ) -> anyhow::Result<()> {
        ensure!(
            depth <= 128 && objects.len() < MAX_ENTRIES,
            "collection inventory exceeds bounds"
        );
        let info = fs::symlink_metadata(path)?;
        ensure!(
            (info.is_file() || info.is_dir())
                && info.uid() == 0
                && info.mode() & 0o7000 == 0
                && (!info.is_file() || info.nlink() == 1),
            "collection object is unsafe"
        );
        objects.push(Object {
            path: path.strip_prefix(root)?.to_owned(),
            device: info.dev(),
            inode: info.ino(),
            directory: info.is_dir(),
            mode: info.mode() & 0o7777,
            size: info.len(),
            mtime: info.mtime(),
            mtime_ns: info.mtime_nsec(),
            ctime: info.ctime(),
            ctime_ns: info.ctime_nsec(),
        });
        if info.is_dir() {
            for child in fs::read_dir(path)?.take(MAX_ENTRIES + 1) {
                visit(root, &child?.path(), objects, depth + 1)?;
            }
        }
        Ok(())
    }
    let mut objects = Vec::new();
    visit(work, work, &mut objects, 0)?;
    objects.sort_by(|left, right| {
        right
            .path
            .components()
            .count()
            .cmp(&left.path.components().count())
            .then_with(|| {
                // Preserve the original journal until all other recorded files have gone.
                (left.path == Path::new("upgrade.json"))
                    .cmp(&(right.path == Path::new("upgrade.json")))
            })
            .then_with(|| right.path.cmp(&left.path))
    });
    Ok(objects)
}
fn object_matches(info: &fs::Metadata, object: &Object) -> bool {
    info.dev() == object.device
        && info.ino() == object.inode
        && info.uid() == 0
        && info.mode() & 0o7777 == object.mode
        && info.is_dir() == object.directory
        && (object.directory
            || info.is_file()
                && info.nlink() == 1
                && info.len() == object.size
                && info.mtime() == object.mtime
                && info.mtime_nsec() == object.mtime_ns
                && info.ctime() == object.ctime
                && info.ctime_nsec() == object.ctime_ns)
}
fn remove(candidate: &Candidate) -> anyhow::Result<()> {
    let work = &candidate.journal.plan.work_directory;
    if !snapshot::named_exists(work)? {
        return Ok(());
    }
    execution::verify_work(&candidate.journal)?;
    // No deletion happens before every remaining object and absence are verified.
    let actual = capture(work)?;
    for object in &actual {
        let expected = candidate
            .objects
            .iter()
            .find(|expected| expected.path == object.path)
            .context("unknown collection object")?;
        let info = fs::symlink_metadata(work.join(&object.path))?;
        ensure!(
            object_matches(&info, expected),
            "collection object inode or metadata changed"
        );
    }
    execution::cleanup_completed(&candidate.journal)?;
    for object in &candidate.objects {
        let path = work.join(&object.path);
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            )
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        ensure!(
            object_matches(&file.metadata()?, object),
            "collection object changed before removal"
        );
        if object.directory {
            fs::remove_dir(&path)?;
        } else {
            fs::remove_file(&path)?;
        }
        snapshot::sync_parent(&path)?;
    }
    Ok(())
}
fn save(path: &Path, record: &Record) -> anyhow::Result<()> {
    ensure!(
        serde_json::to_vec(record)?.len() as u64 <= MAX_RECORD,
        "collection record exceeds bound"
    );
    snapshot::atomic_json(path, record)
}
fn run_record(path: &Path, record: &mut Record) -> anyhow::Result<()> {
    let parent = fs::symlink_metadata(path.parent().context("collection parent missing")?)?;
    ensure!(
        parent.is_dir() && parent.uid() == 0 && parent.mode() & 0o7777 == 0o700,
        "collection parent is unsafe"
    );
    ensure!(
        parent.dev() == record.parent_device && parent.ino() == record.parent_inode,
        "collection parent changed"
    );
    for index in 0..record.retired_records.len() {
        let retired = &record.retired_records[index];
        if retired.removed {
            continue;
        }
        ensure!(
            retired.path.parent() == path.parent()
                && retired.path != path
                && retired
                    .path
                    .file_stem()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| uuid::Uuid::parse_str(name)
                        .is_ok_and(|id| id.get_version_num() == 4 && id.to_string() == name)),
            "retired collection record mapping differs"
        );
        ensure!(
            !references(&record.root, &retired.path, Some(path))?,
            "retired record is referenced"
        );
        if snapshot::named_exists(&retired.path)? {
            let info = fs::symlink_metadata(&retired.path)?;
            ensure!(
                info.is_file()
                    && info.uid() == 0
                    && info.nlink() == 1
                    && info.mode() & 0o7777 == 0o600
                    && info.dev() == retired.device
                    && info.ino() == retired.inode
                    && snapshot::digest_file(&retired.path)? == retired.sha256,
                "retired collection record changed"
            );
            let old: Record =
                serde_json::from_slice(&snapshot::read_bounded(&retired.path, MAX_RECORD)?)?;
            validate_closed_record(&retired.path, &old, &record.root, &parent, &record.policy)?;
            fs::remove_file(&retired.path)?;
            snapshot::sync_parent(&retired.path)?;
        }
        record.retired_records[index].removed = true;
        save(path, record)?;
    }
    for index in 0..record.candidates.len() {
        let candidate = &record.candidates[index];
        if candidate.removed {
            continue;
        }
        let work = &candidate.journal.plan.work_directory;
        ensure!(
            work.parent() == Some(record.root.join("maintenance/upgrades").as_path())
                && work.file_name().and_then(|v| v.to_str())
                    == Some(candidate.journal.operation_id.to_string().as_str()),
            "collection target mapping differs"
        );
        ensure!(
            matches!(
                candidate.journal.phase,
                UpgradePhase::Ready | UpgradePhase::RolledBack
            ) && expired(&candidate.journal, &record.policy)?
                && !references(&record.root, work, Some(path))?,
            "collection target is incomplete, retained, or referenced"
        );
        ensure!(
            candidate.objects.len() <= MAX_ENTRIES,
            "collection object count exceeds bound"
        );
        let mut paths = BTreeSet::new();
        for object in &candidate.objects {
            ensure!(
                paths.insert(&object.path)
                    && (object.path.as_os_str().is_empty()
                        || object
                            .path
                            .components()
                            .all(|part| matches!(part, std::path::Component::Normal(_)))
                            && object.path.components().collect::<PathBuf>() == object.path),
                "collection object mapping repeats or escapes"
            );
        }
        ensure!(
            candidate
                .objects
                .iter()
                .any(|object| object.path.as_os_str().is_empty()),
            "collection root authority missing"
        );
        remove(candidate)?;
        record.candidates[index].removed = true;
        save(path, record)?;
    }
    record.complete = true;
    record.completed_at_micros.get_or_insert(now()?);
    save(path, record)
}
fn validate_closed_record(
    path: &Path,
    record: &Record,
    root: &Path,
    parent: &fs::Metadata,
    policy: &RetentionPolicy,
) -> anyhow::Result<()> {
    ensure!(
        record.version == 1
            && record.root == root
            && record.operation_id.get_version_num() == 4
            && path.file_stem().and_then(|name| name.to_str())
                == Some(record.operation_id.to_string().as_str())
            && record.parent_device == parent.dev()
            && record.parent_inode == parent.ino()
            && record.complete
            && record.candidates.len() <= 4096
            && record.retired_records.len() <= 4096,
        "completed collection record authority differs"
    );
    let completed = record
        .completed_at_micros
        .context("collection completion time missing")?;
    ensure!(
        now()?
            .checked_sub(completed)
            .is_some_and(|age| age / 1_000_000 >= policy.minimum_age_seconds),
        "completed collection record is retained by age"
    );
    ensure!(
        record.retired_records.iter().all(|entry| entry.removed),
        "collection metadata cleanup remains unfinished"
    );
    for candidate in &record.candidates {
        let work = &candidate.journal.plan.work_directory;
        ensure!(
            candidate.removed
                && work.parent() == Some(root.join("maintenance/upgrades").as_path())
                && work.file_name().and_then(|name| name.to_str())
                    == Some(candidate.journal.operation_id.to_string().as_str())
                && !snapshot::named_exists(work)?,
            "old transaction still has recovery materials"
        );
    }
    Ok(())
}
fn closed_records(
    root: &Path,
    policy: &RetentionPolicy,
    retained: &mut Vec<Decision>,
) -> anyhow::Result<Vec<RetiredRecord>> {
    let parent = root.join("maintenance/collections");
    if !snapshot::named_exists(&parent)? {
        return Ok(Vec::new());
    }
    let parent_info = fs::symlink_metadata(&parent)?;
    ensure!(
        parent_info.is_dir() && parent_info.uid() == 0 && parent_info.mode() & 0o7777 == 0o700,
        "collection parent is unsafe"
    );
    let mut records = Vec::new();
    for path in entries(&parent)? {
        let result = (|| -> anyhow::Result<_> {
            let info = fs::symlink_metadata(&path)?;
            ensure!(
                info.is_file()
                    && info.uid() == 0
                    && info.mode() & 0o7777 == 0o600
                    && info.nlink() == 1,
                "collection record is unsafe"
            );
            let record: Record =
                serde_json::from_slice(&snapshot::read_bounded(&path, MAX_RECORD)?)?;
            validate_closed_record(
                &path,
                &record,
                root,
                &parent_info,
                &RetentionPolicy {
                    minimum_age_seconds: 0,
                    keep_completed: 0,
                },
            )?;
            Ok((
                record.completed_at_micros,
                RetiredRecord {
                    path: path.clone(),
                    device: info.dev(),
                    inode: info.ino(),
                    sha256: snapshot::digest_file(&path)?,
                    removed: false,
                },
            ))
        })();
        match result {
            Ok(record) => records.push(record),
            Err(_) => retained.push(Decision {
                work_directory: path,
                reason: "unfinished-or-unknown-collection-record",
            }),
        }
    }
    records.sort_by_key(|value| std::cmp::Reverse(value.0));
    let mut result = Vec::new();
    for (index, (completed, record)) in records.into_iter().enumerate() {
        let reason = if index < policy.keep_completed {
            "retained-collection-by-count"
        } else if !completed
            .and_then(|time| now().ok()?.checked_sub(time))
            .is_some_and(|age| age / 1_000_000 >= policy.minimum_age_seconds)
        {
            "retained-collection-by-age"
        } else if references(root, &record.path, None).unwrap_or(true) {
            "referenced-or-reference-unknown"
        } else {
            "eligible"
        };
        if reason == "eligible" {
            result.push(record)
        } else {
            retained.push(Decision {
                work_directory: record.path,
                reason,
            })
        }
    }
    Ok(result)
}
pub fn collect(
    root: &Path,
    policy: RetentionPolicy,
    execute: bool,
    resume: Option<uuid::Uuid>,
    control: &mut impl ServiceControl,
) -> anyhow::Result<serde_json::Value> {
    ensure!(
        policy.keep_completed <= 4096 && policy.minimum_age_seconds <= 100 * 366 * 24 * 60 * 60,
        "retention policy exceeds bounds"
    );
    let lock = native_release::coordinate_root(root, control.inherited_tool_lock())?;
    control.bind_tool_lock(lock.descriptor())?;
    let parent = root.join("maintenance/collections");
    if let Some(operation) = resume {
        ensure!(
            execute && operation.get_version_num() == 4,
            "resuming collection requires an explicit UUIDv4 and execution authorization"
        );
        let path = parent.join(format!("{operation}.json"));
        let parent_info = fs::symlink_metadata(&parent)?;
        ensure!(
            parent_info.is_dir() && parent_info.uid() == 0 && parent_info.mode() & 0o7777 == 0o700,
            "collection parent is unsafe"
        );
        let record_info = fs::symlink_metadata(&path)?;
        ensure!(
            record_info.is_file()
                && record_info.uid() == 0
                && record_info.mode() & 0o7777 == 0o600
                && record_info.nlink() == 1,
            "collection record is unsafe"
        );
        let mut record: Record =
            serde_json::from_slice(&snapshot::read_bounded(&path, MAX_RECORD)?)?;
        ensure!(
            record.version == 1
                && record.operation_id == operation
                && record.root == root
                && record.policy == policy,
            "collection identity or policy differs"
        );
        run_record(&path, &mut record)?;
        return Ok(
            serde_json::json!({"status":"collection-complete","operation_id":operation,"removed":record.candidates.len()}),
        );
    }
    let mut candidates = Vec::new();
    let mut retained = Vec::new();
    for work in entries(&root.join("maintenance/upgrades"))? {
        let journal = match super::inspect(&work) {
            Ok(journal) => journal,
            Err(_) => {
                retained.push(Decision {
                    work_directory: work,
                    reason: "unknown-or-invalid-record",
                });
                continue;
            }
        };
        if !matches!(
            journal.phase,
            UpgradePhase::Ready | UpgradePhase::RolledBack
        ) {
            retained.push(Decision {
                work_directory: work,
                reason: "unfinished-transaction",
            });
            continue;
        }
        if journal.completed_at_micros.is_none() {
            retained.push(Decision {
                work_directory: work,
                reason: "completion-time-unrecorded",
            });
            continue;
        }
        candidates.push(journal);
    }
    candidates.sort_by_key(|journal| std::cmp::Reverse(journal.completed_at_micros));
    let mut approved = Vec::new();
    for (index, journal) in candidates.into_iter().enumerate() {
        let work = journal.plan.work_directory.clone();
        let reason = if index < policy.keep_completed {
            "retained-by-count"
        } else if !expired(&journal, &policy)? {
            "retained-by-age"
        } else if references(root, &work, None).unwrap_or(true) {
            "referenced-or-reference-unknown"
        } else if known_contents(&journal).is_err() {
            "unknown-content-or-startup-obligation"
        } else {
            "eligible"
        };
        if reason != "eligible" {
            retained.push(Decision {
                work_directory: work,
                reason,
            });
            continue;
        }
        approved.push(Candidate {
            objects: capture(&work)?,
            journal,
            removed: false,
        });
    }
    let retired_records = closed_records(root, &policy, &mut retained)?;
    if !execute {
        return Ok(
            serde_json::json!({"status":"collection-plan","policy":policy,"eligible":approved.iter().map(|value|&value.journal.plan.work_directory).collect::<Vec<_>>(),"eligible_collection_records":retired_records.iter().map(|record|&record.path).collect::<Vec<_>>(),"retained":retained}),
        );
    }
    if !snapshot::named_exists(&parent)? {
        snapshot::private_directory(&parent)?;
    }
    let info = fs::symlink_metadata(&parent)?;
    ensure!(
        info.uid() == 0,
        "collection records require administrator ownership"
    );
    let operation = uuid::Uuid::new_v4();
    let path = parent.join(format!("{operation}.json"));
    ensure!(!snapshot::named_exists(&path)?, "collection record exists");
    let mut record = Record {
        version: 1,
        operation_id: operation,
        root: root.to_owned(),
        parent_device: info.dev(),
        parent_inode: info.ino(),
        policy,
        candidates: approved,
        retired_records,
        complete: false,
        completed_at_micros: None,
    };
    save(&path, &record)?;
    run_record(&path, &mut record)?;
    Ok(
        serde_json::json!({"status":"collection-complete","operation_id":operation,"removed":record.candidates.len(),"retained":retained}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Control;
    impl ServiceControl for Control {
        fn is_stopped(&mut self, _: &super::super::UpgradePlan) -> anyhow::Result<bool> {
            Ok(true)
        }
        fn start(&mut self, _: &super::super::UpgradePlan) -> anyhow::Result<()> {
            anyhow::bail!("collection cannot start services")
        }
        fn configuration(
            &mut self,
            _: &Path,
            _: &super::super::UpgradePlan,
            _: Option<&super::super::ReleaseArtifact>,
        ) -> anyhow::Result<serde_json::Value> {
            anyhow::bail!("collection cannot execute product helpers")
        }
        fn validate(
            &mut self,
            _: &Path,
            _: &super::super::UpgradePlan,
            _: Option<&super::super::ReleaseArtifact>,
        ) -> anyhow::Result<super::super::ValidatedState> {
            anyhow::bail!("collection cannot execute product helpers")
        }
        fn ready(
            &mut self,
            _: &super::super::UpgradePlan,
            _: &str,
            _: &str,
        ) -> anyhow::Result<bool> {
            anyhow::bail!("collection cannot probe running products")
        }
    }
    fn policy() -> RetentionPolicy {
        RetentionPolicy {
            minimum_age_seconds: 0,
            keep_completed: 0,
        }
    }
    #[test]
    fn dry_plan_count_and_age_preserve_completed_materials() {
        let (_temporary, journal) = super::super::tests::collection_fixture();
        let root = &journal.plan.native_release.as_ref().unwrap().root;
        let plan = collect(root, policy(), false, None, &mut Control).unwrap();
        assert_eq!(plan["eligible"].as_array().unwrap().len(), 1);
        assert!(journal.plan.work_directory.exists());
        for retained in [
            RetentionPolicy {
                keep_completed: 1,
                ..policy()
            },
            RetentionPolicy {
                minimum_age_seconds: 3600,
                ..policy()
            },
        ] {
            let plan = collect(root, retained, false, None, &mut Control).unwrap();
            assert!(plan["eligible"].as_array().unwrap().is_empty());
            assert!(journal.plan.work_directory.exists());
        }
    }
    #[test]
    fn unknown_and_referenced_materials_are_reported_and_preserved() {
        let (_temporary, journal) = super::super::tests::collection_fixture();
        let root = &journal.plan.native_release.as_ref().unwrap().root;
        let note = journal.plan.work_directory.join("operator-note");
        fs::write(&note, b"preserve").unwrap();
        let result = collect(root, policy(), true, None, &mut Control).unwrap();
        assert_eq!(result["removed"], 0);
        assert!(note.exists());
        fs::remove_file(note).unwrap();
        let other = root
            .join("maintenance/upgrades")
            .join(uuid::Uuid::new_v4().to_string());
        snapshot::private_directory(&other).unwrap();
        snapshot::atomic_json(&other.join("upgrade.json"),&serde_json::json!({"target_binary":journal.plan.work_directory.join("target-payload/bin/xocs")})).unwrap();
        let result = collect(root, policy(), true, None, &mut Control).unwrap();
        assert_eq!(result["removed"], 0);
        assert!(journal.plan.work_directory.exists());
    }
    #[test]
    fn explicit_execution_collects_exact_scope_and_preserves_business_state() {
        let (_temporary, journal) = super::super::tests::collection_fixture();
        let root = &journal.plan.native_release.as_ref().unwrap().root;
        let business = fs::read(journal.plan.data_dir.join("business.txt")).unwrap();
        let result = collect(root, policy(), true, None, &mut Control).unwrap();
        assert_eq!(result["removed"], 1);
        assert!(!journal.plan.work_directory.exists());
        assert_eq!(
            fs::read(journal.plan.data_dir.join("business.txt")).unwrap(),
            business
        );
        let operation = uuid::Uuid::parse_str(result["operation_id"].as_str().unwrap()).unwrap();
        collect(root, policy(), true, Some(operation), &mut Control).unwrap();
    }
    #[test]
    fn durable_collection_resumes_after_partial_backup_deletion() {
        let (_temporary, journal) = super::super::tests::collection_fixture();
        let root = &journal.plan.native_release.as_ref().unwrap().root;
        known_contents(&journal).unwrap();
        let parent = root.join("maintenance/collections");
        snapshot::private_directory(&parent).unwrap();
        let info = fs::symlink_metadata(&parent).unwrap();
        let operation = uuid::Uuid::new_v4();
        let path = parent.join(format!("{operation}.json"));
        let record = Record {
            version: 1,
            operation_id: operation,
            root: root.to_owned(),
            parent_device: info.dev(),
            parent_inode: info.ino(),
            policy: policy(),
            candidates: vec![Candidate {
                objects: capture(&journal.plan.work_directory).unwrap(),
                journal: journal.clone(),
                removed: false,
            }],
            retired_records: Vec::new(),
            complete: false,
            completed_at_micros: None,
        };
        save(&path, &record).unwrap();
        fs::remove_file(journal.plan.work_directory.join("original-binary")).unwrap();
        assert!(super::super::inspect(&journal.plan.work_directory).is_err());
        collect(root, policy(), true, Some(operation), &mut Control).unwrap();
        assert!(!journal.plan.work_directory.exists());
    }
    #[test]
    fn replaced_object_refuses_collection_without_deleting_any_other_object() {
        let (_temporary, journal) = super::super::tests::collection_fixture();
        let root = &journal.plan.native_release.as_ref().unwrap().root;
        let parent = root.join("maintenance/collections");
        snapshot::private_directory(&parent).unwrap();
        let info = fs::symlink_metadata(&parent).unwrap();
        let operation = uuid::Uuid::new_v4();
        let path = parent.join(format!("{operation}.json"));
        let record = Record {
            version: 1,
            operation_id: operation,
            root: root.to_owned(),
            parent_device: info.dev(),
            parent_inode: info.ino(),
            policy: policy(),
            candidates: vec![Candidate {
                objects: capture(&journal.plan.work_directory).unwrap(),
                journal: journal.clone(),
                removed: false,
            }],
            retired_records: Vec::new(),
            complete: false,
            completed_at_micros: None,
        };
        save(&path, &record).unwrap();
        let original = journal.plan.work_directory.join("original-binary");
        let replacement = journal.plan.work_directory.join("replacement");
        fs::write(&replacement, fs::read(&original).unwrap()).unwrap();
        fs::rename(&replacement, &original).unwrap();
        assert!(collect(root, policy(), true, Some(operation), &mut Control).is_err());
        assert!(original.exists());
        assert!(journal.plan.work_directory.join("upgrade.json").exists());
        assert!(journal.plan.work_directory.join("target-payload").exists());
    }
    #[test]
    fn completed_collection_records_follow_the_explicit_age_and_count_policy() {
        let (_temporary, journal) = super::super::tests::collection_fixture();
        let root = &journal.plan.native_release.as_ref().unwrap().root;
        let first = collect(root, policy(), true, None, &mut Control).unwrap();
        let previous = root
            .join("maintenance/collections")
            .join(format!("{}.json", first["operation_id"].as_str().unwrap()));
        assert!(previous.exists());
        let protected = collect(
            root,
            RetentionPolicy {
                minimum_age_seconds: 0,
                keep_completed: 1,
            },
            false,
            None,
            &mut Control,
        )
        .unwrap();
        assert!(
            protected["eligible_collection_records"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        let plan = collect(root, policy(), false, None, &mut Control).unwrap();
        assert_eq!(
            plan["eligible_collection_records"],
            serde_json::json!([previous])
        );
        assert!(previous.exists());
        collect(root, policy(), true, None, &mut Control).unwrap();
        assert!(!previous.exists());
        assert!(root.join("state/business.txt").exists());
    }
    #[test]
    fn retired_record_deletion_resumes_using_its_original_authority() {
        let (_temporary, journal) = super::super::tests::collection_fixture();
        let root = &journal.plan.native_release.as_ref().unwrap().root;
        collect(root, policy(), true, None, &mut Control).unwrap();
        let parent = root.join("maintenance/collections");
        let info = fs::symlink_metadata(&parent).unwrap();
        let mut retained = Vec::new();
        let retired = closed_records(root, &policy(), &mut retained).unwrap();
        assert_eq!(retired.len(), 1);
        let original = retired[0].path.clone();
        let operation = uuid::Uuid::new_v4();
        let path = parent.join(format!("{operation}.json"));
        let record = Record {
            version: 1,
            operation_id: operation,
            root: root.to_owned(),
            parent_device: info.dev(),
            parent_inode: info.ino(),
            policy: policy(),
            candidates: Vec::new(),
            retired_records: retired,
            complete: false,
            completed_at_micros: None,
        };
        save(&path, &record).unwrap();
        fs::remove_file(&original).unwrap();
        collect(root, policy(), true, Some(operation), &mut Control).unwrap();
        let record: Record =
            serde_json::from_slice(&snapshot::read_bounded(&path, MAX_RECORD).unwrap()).unwrap();
        assert!(
            record.complete
                && record.retired_records[0].removed
                && record.completed_at_micros.is_some()
        );
    }
}
