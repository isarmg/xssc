//! SHA-256-verified payloads within one installation root. Configuration and persistent
//! data never enter the list of files this module replaces.
use super::{Entry, ReleaseResource, UpgradeJournal, UpgradePlan, UpgradeRelease, snapshot};
use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    os::{
        fd::AsFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Component, Path, PathBuf},
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadFile {
    pub path: PathBuf,
    pub mode: String,
    pub size: u64,
    pub sha256: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageService {
    pub name: String,
    pub path: PathBuf,
    pub role: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageManifest {
    pub manifest_version: u32,
    pub identity: xcsc::contracts::ReleaseIdentity,
    pub schema_identity: xcsc::contracts::SchemaIdentity,
    pub server: PathBuf,
    pub setup: PathBuf,
    pub services: Vec<PackageService>,
    pub files: Vec<PayloadFile>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseArtifact {
    pub protocol: String,
    pub entrypoint: PathBuf,
    pub setup: PathBuf,
    pub tree_sha256: String,
    pub files: Vec<PayloadFile>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeReleasePlan {
    pub root: PathBuf,
    pub source_manifest: PathBuf,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NativeBackup {
    pub source_entries: Vec<Entry>,
    pub target_entries: Vec<Entry>,
    pub root_device: u64,
    pub root_inode: u64,
    pub source_recovery_started: bool,
}

fn relative(path: &Path) -> anyhow::Result<()> {
    ensure!(
        path.to_str()
            .is_some_and(|name| !name.chars().any(char::is_control)),
        "payload paths contain control characters"
    );
    ensure!(
        !path.as_os_str().is_empty()
            && path.to_str().is_some()
            && path.as_os_str().as_encoded_bytes().len() <= 4096
            && path
                .components()
                .all(|part| matches!(part, Component::Normal(_)))
            && path.components().collect::<PathBuf>().as_os_str() == path.as_os_str(),
        "invalid payload relative path"
    );
    Ok(())
}
fn payload_path(path: &Path) -> anyhow::Result<()> {
    relative(path)?;
    ensure!(
        matches!(
            path.components().next().unwrap().as_os_str().to_str(),
            Some("bin" | "libexec" | "share")
        ) || matches!(
            path.to_str(),
            Some("install.sh" | "maintenance.sh" | "upgrade.sh")
        ),
        "payload cannot replace configuration or persistent state"
    );
    ensure!(
        path != Path::new("share/package.json") && path != Path::new("share/package.sha256"),
        "metadata cannot hash itself"
    );
    Ok(())
}
fn mode(file: &PayloadFile) -> anyhow::Result<u32> {
    match file.mode.as_str() {
        "0755" => Ok(0o755),
        "0644" => Ok(0o644),
        _ => anyhow::bail!("unsupported payload permissions"),
    }
}
fn validate_files(files: &[PayloadFile]) -> anyhow::Result<()> {
    ensure!(
        !files.is_empty() && files.len() <= 4096,
        "invalid payload count"
    );
    let mut paths = BTreeSet::new();
    let mut total = 0u64;
    for file in files {
        ensure!(
            file.size <= 512 * 1024 * 1024,
            "payload file exceeds size bound"
        );
        total = total
            .checked_add(file.size)
            .context("payload size overflow")?;
        ensure!(
            total <= 2 * 1024 * 1024 * 1024,
            "payload exceeds total size bound"
        );
        payload_path(&file.path)?;
        mode(file)?;
        super::validate_digest(&file.sha256)?;
        ensure!(paths.insert(&file.path), "duplicate payload path");
    }
    for file in files {
        ensure!(
            !paths
                .iter()
                .any(|other| *other != &file.path && file.path.starts_with(other)),
            "payload file and directory overlap"
        );
    }
    Ok(())
}
fn validate_manifest(manifest: &PackageManifest) -> anyhow::Result<()> {
    ensure!(
        manifest.manifest_version == 1,
        "unsupported package contract"
    );
    manifest.identity.validate()?;
    let version = manifest.identity.version.split('.').collect::<Vec<_>>();
    ensure!(
        version.len() == 3
            && version.iter().all(|part| !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (*part == "0" || !part.starts_with('0'))),
        "release version must be canonical major.minor.patch"
    );
    manifest.schema_identity.validate()?;
    ensure!(
        manifest.schema_identity.schema_revision < (1u64 << 53),
        "schema revision exceeds wire bound"
    );
    ensure!(
        manifest.schema_identity.application == manifest.identity.product,
        "schema product differs"
    );
    ensure!(
        matches!(
            manifest.identity.product.as_str(),
            "xcos" | "xczs" | "xocs" | "xscs" | "xsos" | "xszs"
        ),
        "unsupported server product"
    );
    ensure!(
        manifest.server == Path::new("bin").join(&manifest.identity.product)
            && manifest.setup == Path::new("libexec/setup"),
        "uncontrolled executable layout"
    );
    validate_files(&manifest.files)?;
    for path in [&manifest.server, &manifest.setup] {
        ensure!(
            manifest
                .files
                .iter()
                .any(|file| &file.path == path && file.mode == "0755"),
            "verified executable absent"
        );
    }
    ensure!(
        !manifest.services.is_empty() && manifest.services.len() <= 2,
        "invalid writer count"
    );
    let mut roles = BTreeSet::new();
    let mut names = BTreeSet::new();
    for service in &manifest.services {
        ensure!(
            (service.role == "server"
                && service.name == format!("{}.service", manifest.identity.product))
                || (manifest.identity.product == "xcos"
                    && service.role == "media"
                    && service.name == "xcos-mediamtx.service"),
            "uncontrolled package writer"
        );
        super::validate_service(&service.name)?;
        super::validate_service_role(&service.role)?;
        ensure!(
            roles.insert(&service.role) && names.insert(&service.name),
            "duplicate package writer"
        );
        ensure!(
            service.path == Path::new("share/systemd").join(&service.name)
                && manifest.files.iter().any(|file| file.path == service.path),
            "writer template absent from verified payload"
        );
    }
    ensure!(
        manifest
            .services
            .iter()
            .filter(|service| service.role == "server")
            .count()
            == 1,
        "main writer absent"
    );
    Ok(())
}
pub(super) fn validate_plan(plan: &UpgradePlan) -> anyhow::Result<()> {
    let native = plan
        .native_release
        .as_ref()
        .context("fixed-root package plan required")?;
    snapshot::require_path(&native.root)?;
    ensure!(
        native.root != Path::new("/"),
        "installation root cannot be filesystem root"
    );
    ensure!(
        native.source_manifest == native.root.join("share/package.json")
            && plan.config == native.root.join("config/config.json"),
        "nonstandard fixed-root paths"
    );
    snapshot::require_path(&plan.installed_binary)?;
    ensure!(
        plan.installed_binary.parent() == Some(native.root.join("bin").as_path()),
        "executable escaped ROOT/bin"
    );
    let operation = plan
        .work_directory
        .file_name()
        .and_then(|name| name.to_str())
        .context("upgrade work directory needs an operation UUID")?;
    let operation_id = uuid::Uuid::parse_str(operation)?;
    ensure!(
        operation_id.get_version_num() == 4
            && operation_id.to_string() == operation
            && plan.work_directory.parent()
                == Some(native.root.join("maintenance/upgrades").as_path()),
        "recovery must be ROOT/maintenance/upgrades/canonical-v4-UUID"
    );
    ensure!(
        !plan.target_binary.starts_with(native.root.join("bin"))
            && plan.target_binary != plan.installed_binary,
        "target overlaps installed payload"
    );
    for resource in &plan.resources {
        ensure!(
            resource.path != native.root && !native.root.starts_with(&resource.path),
            "state root contains installation"
        );
        for name in ["bin", "libexec", "share", "maintenance", "run"] {
            let reserved = native.root.join(name);
            ensure!(
                !resource.path.starts_with(&reserved) && !reserved.starts_with(&resource.path),
                "state and controlled installation paths overlap"
            );
        }
    }
    Ok(())
}
fn root(plan: &UpgradePlan) -> anyhow::Result<&Path> {
    Ok(&plan
        .native_release
        .as_ref()
        .context("fixed-root plan required")?
        .root)
}
fn controlled_directory(path: &Path) -> anyhow::Result<fs::Metadata> {
    snapshot::require_path(path)?;
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.mode() & 0o7022 == 0,
        "payload directory must be administrator controlled"
    );
    Ok(metadata)
}
pub(super) fn installed_binary(plan: &UpgradePlan) -> anyhow::Result<PathBuf> {
    validate_plan(plan)?;
    Ok(plan.installed_binary.clone())
}
fn input_root(plan: &UpgradePlan, artifact: &ReleaseArtifact) -> anyhow::Result<PathBuf> {
    let mut directory = plan.target_binary.clone();
    for _ in artifact.entrypoint.components() {
        ensure!(directory.pop(), "target has no payload root");
    }
    ensure!(
        directory.join(&artifact.entrypoint) == plan.target_binary,
        "target differs from verified executable"
    );
    snapshot::require_path(&directory)?;
    ensure!(
        plan.release_manifest == directory.join("share/package.json")
            && plan.release_checksum == directory.join("share/package.sha256"),
        "metadata escaped target payload"
    );
    Ok(directory)
}
pub(super) fn verify_checksum(raw: &[u8], checksum: &[u8]) -> anyhow::Result<()> {
    let expected = format!("{}\n", super::digest_hex(Sha256::digest(raw)));
    ensure!(
        checksum == expected.as_bytes(),
        "package manifest SHA-256 mismatch"
    );
    Ok(())
}
fn source_manifest_verified(plan: &UpgradePlan) -> anyhow::Result<PackageManifest> {
    let native = plan
        .native_release
        .as_ref()
        .context("fixed-root plan required")?;
    controlled_directory(&native.root)?;
    let raw = snapshot::read_bounded(&native.source_manifest, super::MAX_JSON)?;
    verify_checksum(
        &raw,
        &snapshot::read_bounded(&native.root.join("share/package.sha256"), 65)?,
    )?;
    let manifest: PackageManifest = serde_json::from_slice(&raw)?;
    validate_manifest(&manifest)?;
    ensure!(
        native.root.join(&manifest.server) == plan.installed_binary,
        "installed path differs from source authority"
    );
    payload_entries(&native.root, &manifest.files, plan.max_backup_bytes)?;
    Ok(manifest)
}

pub(super) fn current_package(plan: &UpgradePlan) -> anyhow::Result<PackageManifest> {
    source_manifest_verified(plan)
}
pub(super) fn package_to_release(plan: &UpgradePlan, raw: &[u8]) -> anyhow::Result<UpgradeRelease> {
    let target: PackageManifest = serde_json::from_slice(raw)?;
    validate_manifest(&target)?;
    let source = source_manifest_verified(plan)?;
    ensure!(
        source.services == target.services,
        "upgrade cannot silently change state writers"
    );
    ensure!(
        source
            .services
            .iter()
            .any(|service| service.role == "server" && service.name == plan.service),
        "main service differs from verified mapping"
    );
    let mut roles = source
        .services
        .iter()
        .filter(|service| service.role != "server")
        .map(|service| service.role.clone())
        .collect::<Vec<_>>();
    roles.sort();
    for service in &source.services {
        if service.role != "server" {
            ensure!(
                plan.additional_services
                    .iter()
                    .any(|writer| writer.role == service.role && writer.service == service.name),
                "additional writer differs from verified mapping"
            );
        }
    }
    for service in &source.services {
        let old = source
            .files
            .iter()
            .find(|file| file.path == service.path)
            .context("source unit missing")?;
        let new = target
            .files
            .iter()
            .find(|file| file.path == service.path)
            .context("target unit missing")?;
        ensure!(
            old == new,
            "service template changes require an explicit installation contract update"
        );
    }
    let binary_sha256 = target
        .files
        .iter()
        .find(|file| file.path == target.server)
        .context("checksummed server absent")?
        .sha256
        .clone();
    let artifact = ReleaseArtifact {
        protocol: "fixed-root-payload-v1".into(),
        entrypoint: target.server,
        setup: target.setup,
        tree_sha256: payload_digest(&target.files)?,
        files: target.files,
    };
    Ok(UpgradeRelease {
        manifest_version: 1,
        identity: target.identity,
        source_identity: source.identity,
        binary_sha256,
        source_schema: source.schema_identity,
        target_schema: target.schema_identity,
        artifact: Some(artifact),
        resources: plan
            .resources
            .iter()
            .map(|resource| ReleaseResource {
                name: resource.name.clone(),
                kind: resource.kind,
            })
            .collect(),
        additional_service_roles: roles,
    })
}
fn payload_digest(files: &[PayloadFile]) -> anyhow::Result<String> {
    let mut sorted = files.to_vec();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));
    let mut digest = Sha256::new();
    digest.update(b"fixed-root-payload-v1\n");
    digest.update(serde_json::to_vec(&sorted)?);
    Ok(super::digest_hex(digest.finalize()))
}
pub(super) fn validate_artifact(
    plan: &UpgradePlan,
    release: &UpgradeRelease,
) -> anyhow::Result<()> {
    validate_plan(plan)?;
    let artifact = release
        .artifact
        .as_ref()
        .context("checksummed fixed-root payload required")?;
    ensure!(
        artifact.protocol == "fixed-root-payload-v1"
            && artifact.entrypoint == Path::new("bin").join(&release.identity.product)
            && artifact.setup == Path::new("libexec/setup"),
        "unsupported payload layout"
    );
    ensure!(
        root(plan)?.join(&artifact.entrypoint) == plan.installed_binary,
        "source and target executable layout differs"
    );
    validate_files(&artifact.files)?;
    ensure!(
        artifact
            .files
            .iter()
            .any(|file| file.path == artifact.entrypoint
                && file.mode == "0755"
                && file.sha256 == release.binary_sha256)
            && artifact
                .files
                .iter()
                .any(|file| file.path == artifact.setup && file.mode == "0755"),
        "verified executables missing"
    );
    ensure!(
        payload_digest(&artifact.files)? == artifact.tree_sha256,
        "verified payload digest differs"
    );
    input_root(plan, artifact)?;
    Ok(())
}

fn payload_entries(
    directory: &Path,
    files: &[PayloadFile],
    budget: u64,
) -> anyhow::Result<Vec<Entry>> {
    let mut paths: BTreeMap<PathBuf, Option<&PayloadFile>> = BTreeMap::new();
    paths.insert(PathBuf::new(), None);
    for file in files {
        relative(&file.path)?;
        let mut parent = file.path.parent();
        while let Some(path) = parent {
            if path.as_os_str().is_empty() {
                break;
            }
            paths.entry(path.to_owned()).or_insert(None);
            parent = path.parent();
        }
        ensure!(
            paths.insert(file.path.clone(), Some(file)).is_none(),
            "payload paths overlap"
        );
    }
    let mut total = 0u64;
    let mut entries = Vec::with_capacity(paths.len());
    for (relative, authority) in paths {
        let path = if relative.as_os_str().is_empty() {
            directory.to_path_buf()
        } else {
            directory.join(&relative)
        };
        if let Some(file) = authority {
            let held = snapshot::open_regular(&path)?;
            let metadata = held.metadata()?;
            let permissions = mode(file)?;
            ensure!(
                metadata.uid() == rustix::process::geteuid().as_raw()
                    && metadata.mode() & 0o7777 == permissions
                    && metadata.len() == file.size,
                "payload ownership, size or mode differs"
            );
            total = total
                .checked_add(file.size)
                .context("payload size overflow")?;
            ensure!(
                total <= budget && snapshot::digest_file(&path)? == file.sha256,
                "payload budget or checksum differs"
            );
            entries.push(Entry {
                path: relative,
                directory: false,
                mode: permissions,
                bytes: file.size,
                sha256: file.sha256.clone(),
            });
        } else {
            let metadata = controlled_directory(&path)?;
            ensure!(
                metadata.mode() & 0o777 == 0o755,
                "payload directories require 0755"
            );
            entries.push(Entry {
                path: relative,
                directory: true,
                mode: 0o755,
                bytes: 0,
                sha256: String::new(),
            });
        }
    }
    Ok(entries)
}
fn metadata_files(directory: &Path, files: &[PayloadFile]) -> anyhow::Result<Vec<PayloadFile>> {
    let mut output = files.to_vec();
    for name in ["share/package.json", "share/package.sha256"] {
        let path = directory.join(name);
        let metadata = snapshot::open_regular(&path)?.metadata()?;
        ensure!(
            metadata.mode() & 0o7777 == 0o644,
            "package metadata requires 0644"
        );
        output.push(PayloadFile {
            path: PathBuf::from(name),
            mode: "0644".into(),
            size: metadata.len(),
            sha256: snapshot::digest_file(&path)?,
        });
    }
    Ok(output)
}
fn files_from_entries(entries: &[Entry]) -> Vec<PayloadFile> {
    entries
        .iter()
        .filter(|entry| !entry.directory)
        .map(|entry| PayloadFile {
            path: entry.path.clone(),
            mode: format!("{:04o}", entry.mode),
            size: entry.bytes,
            sha256: entry.sha256.clone(),
        })
        .collect()
}
fn verify_inventory(directory: &Path, entries: &[Entry], budget: u64) -> anyhow::Result<()> {
    ensure!(
        payload_entries(directory, &files_from_entries(entries), budget)? == entries,
        "payload inventory changed"
    );
    Ok(())
}
pub(super) fn verify_input(plan: &UpgradePlan, release: &UpgradeRelease) -> anyhow::Result<()> {
    validate_artifact(plan, release)?;
    let artifact = release.artifact.as_ref().unwrap();
    let directory = input_root(plan, artifact)?;
    let expected = payload_entries(
        &directory,
        &metadata_files(&directory, &artifact.files)?,
        plan.max_backup_bytes,
    )?;
    let actual = snapshot::inventory_owned(
        &directory,
        true,
        plan.max_backup_bytes,
        false,
        rustix::process::geteuid().as_raw(),
    )?;
    ensure!(
        actual == expected,
        "undeclared files or directories in target payload"
    );
    Ok(())
}

/// A script passes its held tool.lock through an explicit inherited descriptor.
/// Only the independently opened named inode is accepted. Drop closes the duplicate without unlocking the
/// parent's shared open file description.
pub(super) struct ToolLock {
    _file: File,
}
impl ToolLock {
    /// A child can inherit a duplicate of this open file description without
    /// releasing the coordinator lock held for the whole transaction.
    pub(super) fn descriptor(&self) -> std::os::fd::BorrowedFd<'_> {
        self._file.as_fd()
    }
}
pub(super) fn coordinate(
    plan: &UpgradePlan,
    inherited: Option<std::os::fd::BorrowedFd<'_>>,
) -> anyhow::Result<Option<ToolLock>> {
    Ok(Some(coordinate_root(root(plan)?, inherited)?))
}
pub(super) fn coordinate_root(
    root: &Path,
    inherited: Option<std::os::fd::BorrowedFd<'_>>,
) -> anyhow::Result<ToolLock> {
    ensure!(
        rustix::process::geteuid().as_raw() == 0,
        "installation coordination requires root"
    );
    super::execution::require_trusted(root)?;
    let directory = root.join("maintenance");
    let metadata = controlled_directory(&directory)?;
    ensure!(
        metadata.mode() & 0o7777 == 0o700,
        "maintenance requires 0700"
    );
    let path = directory.join("tool.lock");
    let named = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(&path)?;
    let metadata = named.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.mode() & 0o7777 == 0o600,
        "unsafe tool coordinator lock"
    );
    let file = match inherited {
        Some(descriptor) => {
            let held = rustix::fs::fstat(descriptor)?;
            ensure!(
                held.st_dev == metadata.dev()
                    && held.st_ino == metadata.ino()
                    && held.st_uid == metadata.uid()
                    && held.st_nlink == 1
                    && held.st_mode & 0o7777 == 0o600,
                "inherited coordinator descriptor differs from the controlled lock"
            );
            File::from(rustix::io::dup(descriptor)?)
        }
        None => named,
    };
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)?;
    let current = fs::symlink_metadata(&path)?;
    ensure!(
        current.dev() == metadata.dev() && current.ino() == metadata.ino(),
        "coordinator lock changed"
    );
    Ok(ToolLock { _file: file })
}
pub(super) fn staged_root(journal: &UpgradeJournal) -> anyhow::Result<PathBuf> {
    Ok(super::execution::root(journal)?.join("target-payload"))
}
pub(super) fn staged_binary(journal: &UpgradeJournal) -> anyhow::Result<PathBuf> {
    Ok(staged_root(journal)?.join(
        &journal
            .release
            .artifact
            .as_ref()
            .context("payload required")?
            .entrypoint,
    ))
}
pub(super) fn seal(journal: &mut UpgradeJournal) -> anyhow::Result<()> {
    let source = source_manifest_verified(&journal.plan)?;
    let artifact = journal
        .release
        .artifact
        .as_ref()
        .context("payload required")?;
    let source_root = root(&journal.plan)?;
    let source_entries = payload_entries(
        source_root,
        &metadata_files(source_root, &source.files)?,
        journal.plan.max_backup_bytes,
    )?;
    let input = input_root(&journal.plan, artifact)?;
    verify_input(&journal.plan, &journal.release)?;
    let target_entries = payload_entries(
        &input,
        &metadata_files(&input, &artifact.files)?,
        journal.plan.max_backup_bytes,
    )?;
    let metadata = controlled_directory(source_root)?;
    let staged = staged_root(journal)?;
    snapshot::snapshot_recorded(&input, &staged, &target_entries, |directory, metadata| {
        super::execution::record_payload_stage(journal, directory, metadata)
    })?;
    verify_inventory(&staged, &target_entries, journal.plan.max_backup_bytes)?;
    journal.native_backup = Some(NativeBackup {
        source_entries,
        target_entries,
        root_device: metadata.dev(),
        root_inode: metadata.ino(),
        source_recovery_started: false,
    });
    Ok(())
}
fn verify_parent(journal: &UpgradeJournal) -> anyhow::Result<()> {
    let backup = journal
        .native_backup
        .as_ref()
        .context("payload backup missing")?;
    let metadata = controlled_directory(root(&journal.plan)?)?;
    ensure!(
        metadata.dev() == backup.root_device && metadata.ino() == backup.root_inode,
        "installation root identity changed"
    );
    Ok(())
}
pub(super) fn backup_original(journal: &UpgradeJournal) -> anyhow::Result<u64> {
    verify_parent(journal)?;
    let backup = journal
        .native_backup
        .as_ref()
        .context("payload backup missing")?;
    verify_inventory(
        root(&journal.plan)?,
        &backup.source_entries,
        journal.plan.max_backup_bytes,
    )?;
    snapshot::snapshot(
        root(&journal.plan)?,
        &journal.plan.work_directory.join("original-payload"),
        &backup.source_entries,
    )?;
    verify_original_backup(journal)?;
    backup.source_entries.iter().try_fold(0u64, |total, entry| {
        total
            .checked_add(entry.bytes)
            .context("payload size overflow")
    })
}
pub(super) fn verify_original_backup(journal: &UpgradeJournal) -> anyhow::Result<()> {
    let backup = journal
        .native_backup
        .as_ref()
        .context("payload backup missing")?;
    verify_parent(journal)?;
    verify_inventory(
        &journal.plan.work_directory.join("original-payload"),
        &backup.source_entries,
        journal.plan.max_backup_bytes,
    )
}
pub(super) fn verify_sealed(journal: &UpgradeJournal) -> anyhow::Result<()> {
    let backup = journal
        .native_backup
        .as_ref()
        .context("payload backup missing")?;
    verify_parent(journal)?;
    verify_inventory(
        &staged_root(journal)?,
        &backup.target_entries,
        journal.plan.max_backup_bytes,
    )
}
fn prepare_parent(path: &Path, boundary: &Path) -> anyhow::Result<()> {
    ensure!(path.starts_with(boundary), "payload parent escaped ROOT");
    if path != boundary {
        prepare_parent(path.parent().context("payload parent missing")?, boundary)?;
        if !snapshot::named_exists(path)? {
            fs::create_dir(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
            snapshot::sync_parent(path)?;
        }
    }
    controlled_directory(path)?;
    Ok(())
}
fn known_live(directory: &Path, source: &[Entry], target: &[Entry]) -> anyhow::Result<()> {
    let paths = source
        .iter()
        .chain(target)
        .filter(|entry| !entry.directory)
        .map(|entry| &entry.path)
        .collect::<BTreeSet<_>>();
    for path in paths {
        let named = directory.join(path);
        if !snapshot::named_exists(&named)? {
            continue;
        }
        let metadata = snapshot::open_regular(&named)?.metadata()?;
        let digest = snapshot::digest_file(&named)?;
        ensure!(
            metadata.uid() == rustix::process::geteuid().as_raw()
                && source.iter().chain(target).any(|entry| entry.path == *path
                    && !entry.directory
                    && entry.sha256 == digest
                    && entry.mode == metadata.mode() & 0o7777
                    && entry.bytes == metadata.len()),
            "unknown installed payload; refusing replacement"
        );
    }
    Ok(())
}
fn replace_payload(
    source_root: &Path,
    installed: &Path,
    wanted: &[Entry],
    obsolete: &[Entry],
) -> anyhow::Result<()> {
    known_live(installed, wanted, obsolete)?;
    for entry in wanted.iter().filter(|entry| !entry.directory) {
        let destination = installed.join(&entry.path);
        prepare_parent(destination.parent().unwrap(), installed)?;
        replace_file(
            &source_root.join(&entry.path),
            &destination,
            &entry.sha256,
            entry.mode,
        )?;
    }
    let wanted_paths = wanted
        .iter()
        .map(|entry| &entry.path)
        .collect::<BTreeSet<_>>();
    for entry in obsolete
        .iter()
        .rev()
        .filter(|entry| !entry.directory && !wanted_paths.contains(&entry.path))
    {
        let path = installed.join(&entry.path);
        if snapshot::named_exists(&path)? {
            fs::remove_file(&path)?;
            snapshot::sync_parent(&path)?;
        }
    }
    Ok(())
}

fn replace_file(source: &Path, target: &Path, digest: &str, mode: u32) -> anyhow::Result<()> {
    ensure!(
        snapshot::digest_file(source)? == digest,
        "sealed payload changed before replacement"
    );
    let temporary = target.with_file_name(format!(".upgrade-payload-{}", uuid::Uuid::new_v4()));
    snapshot::copy_regular(source, &temporary, mode)?;
    ensure!(
        snapshot::digest_file(&temporary)? == digest,
        "staged payload checksum differs"
    );
    fs::rename(&temporary, target)?;
    snapshot::sync_parent(target)?;
    ensure!(
        snapshot::digest_file(target)? == digest,
        "installed payload checksum differs"
    );
    Ok(())
}
pub(super) fn install_target(journal: &UpgradeJournal) -> anyhow::Result<()> {
    verify_parent(journal)?;
    verify_sealed(journal)?;
    let backup = journal
        .native_backup
        .as_ref()
        .context("payload backup missing")?;
    replace_payload(
        &staged_root(journal)?,
        root(&journal.plan)?,
        &backup.target_entries,
        &backup.source_entries,
    )?;
    verify_inventory(
        root(&journal.plan)?,
        &backup.target_entries,
        journal.plan.max_backup_bytes,
    )
}
pub(super) fn original_needs_repair(journal: &UpgradeJournal) -> anyhow::Result<bool> {
    verify_parent(journal)?;
    let backup = journal
        .native_backup
        .as_ref()
        .context("payload backup missing")?;
    Ok(verify_inventory(
        root(&journal.plan)?,
        &backup.source_entries,
        journal.plan.max_backup_bytes,
    )
    .is_err())
}
pub(super) fn permitted_missing_original(journal: &UpgradeJournal) -> anyhow::Result<bool> {
    verify_parent(journal)?;
    let backup = journal
        .native_backup
        .as_ref()
        .context("payload backup missing")?;
    known_live(
        root(&journal.plan)?,
        &backup.source_entries,
        &backup.target_entries,
    )?;
    Ok(matches!(
        journal.phase,
        super::UpgradePhase::SwitchIntent | super::UpgradePhase::RecoveryRestoring
    ))
}
pub(super) fn restore_original(journal: &UpgradeJournal) -> anyhow::Result<()> {
    verify_original_backup(journal)?;
    let backup = journal
        .native_backup
        .as_ref()
        .context("payload backup missing")?;
    replace_payload(
        &journal.plan.work_directory.join("original-payload"),
        root(&journal.plan)?,
        &backup.source_entries,
        &backup.target_entries,
    )?;
    verify_inventory(
        root(&journal.plan)?,
        &backup.source_entries,
        journal.plan.max_backup_bytes,
    )
}
pub(super) fn program_status(journal: &UpgradeJournal) -> anyhow::Result<&'static str> {
    verify_parent(journal)?;
    let backup = journal
        .native_backup
        .as_ref()
        .context("payload backup missing")?;
    if verify_inventory(
        root(&journal.plan)?,
        &backup.source_entries,
        journal.plan.max_backup_bytes,
    )
    .is_ok()
    {
        return Ok("original");
    }
    if verify_inventory(
        root(&journal.plan)?,
        &backup.target_entries,
        journal.plan.max_backup_bytes,
    )
    .is_ok()
    {
        return Ok("target");
    }
    known_live(
        root(&journal.plan)?,
        &backup.source_entries,
        &backup.target_entries,
    )?;
    Ok("partial-switch")
}
