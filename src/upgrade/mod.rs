//! Offline upgrade orchestration. Product code owns read-only current-state
//! validation; this module owns maintenance, snapshots, release switching and
//! interruption recovery. No server runtime links this module.

pub mod collection;
mod execution;
mod native_release;
mod process;
mod runtime_locks;
mod snapshot;
mod startup_control;
pub use native_release::{NativeReleasePlan, ReleaseArtifact};
#[cfg(test)]
mod tests;

use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, ensure};
use process::{run_bounded, run_product};
use serde::{Deserialize, Serialize};
use snapshot::Entry;
use uuid::Uuid;
use xcsc::contracts::{ReleaseIdentity, SchemaIdentity};
use xcsc::state_file::PrivateStateDirectory;

const JOURNAL: &str = "upgrade.json";
const MAX_JSON: u64 = 1024 * 1024;
const MAX_JOURNAL: u64 = 128 * 1024 * 1024;
const DEFAULT_BACKUP_BYTES: u64 = 1024 * 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceType {
    File,
    Directory,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PersistentResource {
    pub name: String,
    pub path: PathBuf,
    pub kind: ResourceType,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseResource {
    pub name: String,
    pub kind: ResourceType,
}

/// Internal transaction derived from the checksum-verified exact package bytes.
/// Resource names and schema identities are supplied by this tool's controlled
/// release definition. A format conversion requires an explicit implementation;
/// editing an identity cannot change the actual structure.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpgradeRelease {
    pub manifest_version: u32,
    pub identity: ReleaseIdentity,
    pub source_identity: ReleaseIdentity,
    pub binary_sha256: String,
    pub source_schema: SchemaIdentity,
    pub target_schema: SchemaIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<ReleaseArtifact>,
    pub resources: Vec<ReleaseResource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_service_roles: Vec<String>,
}

/// Tool-owned deployment mapping for every additional persistent-state writer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdditionalService {
    pub role: String,
    pub service: String,
}

/// A future release that changes persistent structure needs an implementation
/// for that actual release. This tool currently preserves the exact contract.
fn validate_state_transition(release: &UpgradeRelease) -> anyhow::Result<()> {
    release.source_schema.validate()?;
    release.target_schema.validate()?;
    ensure!(
        release.source_schema.application == release.target_schema.application,
        "a verified transition cannot change the product owning the data"
    );
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpgradePlan {
    pub plan_version: u32,
    pub service: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_services: Vec<AdditionalService>,
    pub installed_binary: PathBuf,
    pub target_binary: PathBuf,
    pub release_manifest: PathBuf,
    pub release_checksum: PathBuf,
    pub config: PathBuf,
    pub data_dir: PathBuf,
    pub resources: Vec<PersistentResource>,
    pub work_directory: PathBuf,
    pub readiness_address: SocketAddr,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_backup_bytes")]
    pub max_backup_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_release: Option<NativeReleasePlan>,
}

fn default_timeout() -> u64 {
    60
}
fn default_backup_bytes() -> u64 {
    DEFAULT_BACKUP_BYTES
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UpgradePhase {
    Prechecked,
    MaintenanceIntent,
    MaintenanceAcquired,
    BackupStarted,
    BackupComplete,
    Validated,
    SwitchIntent,
    Switched,
    StartIntent,
    Ready,
    RecoveryMaintenanceIntent,
    RecoveryRestoring,
    RecoveryStartIntent,
    RolledBack,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ResourceBackup {
    resource: PersistentResource,
    entries: Vec<Entry>,
    ownership: Vec<snapshot::Ownership>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpgradeJournal {
    pub journal_version: u32,
    #[serde(deserialize_with = "canonical_operation")]
    pub operation_id: Uuid,
    pub phase: UpgradePhase,
    pub completed_at_micros: Option<u64>,
    pub recovery_outcome: Option<String>,
    pub plan: UpgradePlan,
    pub release: UpgradeRelease,
    pub original_binary_sha256: String,
    pub original_binary_mode: u32,
    /// Set before releasing maintenance, so a crash cannot assert absence of
    /// writes simply because the start command or readiness observation failed.
    pub new_program_may_have_written: bool,
    pub recovered_program_may_have_written: bool,
    pub backup_complete: bool,
    pub shared_paths: Vec<PathBuf>,
    business_paths: Vec<PathBuf>,
    runtime_locks: Vec<runtime_locks::Authority>,
    backups: Vec<ResourceBackup>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    native_backup: Option<native_release::NativeBackup>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    work_directory_seal: Option<execution::StageAuthority>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    payload_stage_seal: Option<execution::StageAuthority>,
    startup_control: Option<startup_control::Authority>,
}

fn canonical_operation<'de, D>(deserializer: D) -> Result<Uuid, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;
    let operation = Uuid::parse_str(&encoded).map_err(serde::de::Error::custom)?;
    if operation.get_version_num() != 4 || operation.to_string() != encoded {
        return Err(serde::de::Error::custom(
            "operation must be a canonical v4 UUID",
        ));
    }
    Ok(operation)
}

#[derive(Clone, Debug, Serialize)]
pub struct UpgradeFailure {
    pub code: &'static str,
    pub message: String,
    pub work_directory: Option<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
enum StructureFailure {
    #[error("Existing data structure does not match the declared current-source structure")]
    Incompatible,
    #[error("Product read-only structure validation failed or produced unauthorized writes")]
    Validation,
    #[error("Declared persistent paths are not fully included in upgrade protection")]
    ResourceCoverage,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatedState {
    pub schema_identity: SchemaIdentity,
    pub state_paths: Vec<PathBuf>,
}

#[derive(Clone, Debug, Serialize)]
pub struct UpgradeInspection {
    pub journal: UpgradeJournal,
    pub installed_program: &'static str,
    pub installed_binary_sha256: Option<String>,
    pub persistent_state_verification: &'static str,
}

impl std::fmt::Display for UpgradeFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}
impl std::error::Error for UpgradeFailure {}

fn failure(code: &'static str, message: impl Into<String>, work: Option<&Path>) -> UpgradeFailure {
    UpgradeFailure {
        code,
        message: message.into(),
        work_directory: work.map(Path::to_owned),
    }
}

/// Service control is separate from the durable state machine so tests can
/// exercise real filesystem transitions without manipulating the host service
/// manager. Production always uses the systemd implementation below.
pub trait ServiceControl {
    fn inherited_tool_lock(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        None
    }
    fn bind_tool_lock(&mut self, _descriptor: std::os::fd::BorrowedFd<'_>) -> anyhow::Result<()> {
        Ok(())
    }
    fn bind_instance_locks(
        &mut self,
        _locks: &[(PathBuf, std::os::fd::BorrowedFd<'_>)],
    ) -> anyhow::Result<()> {
        Ok(())
    }
    fn release_instance_locks(&mut self) {}
    fn verify_release_identity(
        &mut self,
        _binary: &Path,
        _plan: &UpgradePlan,
        _identity: &ReleaseIdentity,
    ) -> anyhow::Result<()> {
        Ok(())
    }
    fn verify_service_identity(&mut self, _plan: &UpgradePlan) -> anyhow::Result<()> {
        Ok(())
    }
    fn establish_startup_control(&mut self, _journal: &mut UpgradeJournal) -> anyhow::Result<()> {
        Ok(())
    }
    fn verify_startup_control(&mut self, _journal: &UpgradeJournal) -> anyhow::Result<()> {
        Ok(())
    }
    fn release_startup_control(&mut self, _journal: &mut UpgradeJournal) -> anyhow::Result<()> {
        Ok(())
    }
    fn stop(&mut self, _journal: &mut UpgradeJournal) -> anyhow::Result<()> {
        Ok(())
    }
    fn is_stopped(&mut self, plan: &UpgradePlan) -> anyhow::Result<bool>;
    fn start(&mut self, plan: &UpgradePlan) -> anyhow::Result<()>;
    fn start_recovered(&mut self, journal: &UpgradeJournal) -> anyhow::Result<&'static str> {
        self.start(&journal.plan)?;
        Ok("restored-ready-required")
    }
    fn configuration(
        &mut self,
        binary: &Path,
        plan: &UpgradePlan,
        artifact: Option<&ReleaseArtifact>,
    ) -> anyhow::Result<serde_json::Value>;
    fn validate(
        &mut self,
        binary: &Path,
        plan: &UpgradePlan,
        artifact: Option<&ReleaseArtifact>,
    ) -> anyhow::Result<ValidatedState>;
    fn ready(
        &mut self,
        plan: &UpgradePlan,
        binary_sha256: &str,
        service_identity: &str,
    ) -> anyhow::Result<bool>;
}

#[derive(Default)]
pub struct SystemdControl {
    tool_lock: Option<File>,
    instance_locks: Vec<(PathBuf, File)>,
}

impl SystemdControl {
    pub fn with_tool_lock(descriptor: Option<i32>) -> anyhow::Result<Self> {
        Ok(Self {
            instance_locks: Vec::new(),
            tool_lock: descriptor
                .map(process::duplicate_inherited_file)
                .transpose()?,
        })
    }
    fn descriptor(&self) -> anyhow::Result<std::os::fd::BorrowedFd<'_>> {
        use std::os::fd::AsFd;
        Ok(self
            .tool_lock
            .as_ref()
            .context("helper invocation lacks the installation tool lock")?
            .as_fd())
    }
}

impl ServiceControl for SystemdControl {
    fn inherited_tool_lock(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        use std::os::fd::AsFd;
        self.tool_lock.as_ref().map(AsFd::as_fd)
    }
    fn bind_tool_lock(&mut self, descriptor: std::os::fd::BorrowedFd<'_>) -> anyhow::Result<()> {
        self.tool_lock = Some(File::from(rustix::io::dup(descriptor)?));
        Ok(())
    }
    fn bind_instance_locks(
        &mut self,
        locks: &[(PathBuf, std::os::fd::BorrowedFd<'_>)],
    ) -> anyhow::Result<()> {
        self.instance_locks = locks
            .iter()
            .map(|(path, fd)| Ok((path.clone(), File::from(rustix::io::dup(*fd)?))))
            .collect::<anyhow::Result<_>>()?;
        Ok(())
    }
    fn release_instance_locks(&mut self) {
        self.instance_locks.clear();
    }
    fn verify_release_identity(
        &mut self,
        binary: &Path,
        plan: &UpgradePlan,
        expected: &ReleaseIdentity,
    ) -> anyhow::Result<()> {
        // Verified metadata and complete payload verification own this identity.
        // Product runtimes expose no offline identity or maintenance command.
        expected.validate()?;
        ensure!(
            snapshot::open_regular(binary)?.metadata()?.mode() & 0o111 != 0,
            "verified product entrypoint is not executable"
        );
        let _ = plan;
        Ok(())
    }
    fn verify_service_identity(&mut self, plan: &UpgradePlan) -> anyhow::Result<()> {
        execution::verify_service(plan)
    }
    fn establish_startup_control(&mut self, journal: &mut UpgradeJournal) -> anyhow::Result<()> {
        startup_control::establish(journal)
    }
    fn verify_startup_control(&mut self, journal: &UpgradeJournal) -> anyhow::Result<()> {
        startup_control::verify(journal)
    }
    fn release_startup_control(&mut self, journal: &mut UpgradeJournal) -> anyhow::Result<()> {
        startup_control::release(journal)
    }
    fn stop(&mut self, journal: &mut UpgradeJournal) -> anyhow::Result<()> {
        startup_control::stop(journal)
    }
    fn is_stopped(&mut self, plan: &UpgradePlan) -> anyhow::Result<bool> {
        let bytes = run_bounded(
            "/usr/bin/systemctl",
            &[
                "show".into(),
                plan.service.clone(),
                "--property=LoadState".into(),
                "--property=MainPID".into(),
                "--property=ActiveState".into(),
            ],
            plan.timeout_seconds,
        )?;
        stopped_service_report(&bytes)
    }

    fn start(&mut self, plan: &UpgradePlan) -> anyhow::Result<()> {
        for service in plan
            .additional_services
            .iter()
            .map(|entry| &entry.service)
            .chain(std::iter::once(&plan.service))
        {
            run_bounded(
                "/usr/bin/systemctl",
                &["start".into(), service.clone()],
                plan.timeout_seconds,
            )?;
        }
        Ok(())
    }

    fn start_recovered(&mut self, journal: &UpgradeJournal) -> anyhow::Result<&'static str> {
        let required = startup_control::original_required_services(journal)?;
        for service in &required {
            run_bounded(
                "/usr/bin/systemctl",
                &["start".into(), service.clone()],
                journal.plan.timeout_seconds,
            )?;
        }
        Ok(
            if required.len() == journal.plan.additional_services.len() + 1 {
                "restored-ready-required"
            } else if required.is_empty() {
                "restored-original-stopped"
            } else {
                "restored-original-partial"
            },
        )
    }
    fn configuration(
        &mut self,
        binary: &Path,
        plan: &UpgradePlan,
        artifact: Option<&ReleaseArtifact>,
    ) -> anyhow::Result<serde_json::Value> {
        let helper = setup_for_binary(binary, plan, artifact)?;
        let bytes = run_product(
            &helper,
            plan,
            &[
                "--product".into(),
                service_product(plan)?,
                "--root".into(),
                installation_root(plan)?.to_string_lossy().into_owned(),
                "--config".into(),
                plan.config.to_string_lossy().into_owned(),
                "--json".into(),
                "config-validate".into(),
            ],
            plan.timeout_seconds,
            self.descriptor()?,
            &self.instance_locks,
        )?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    fn validate(
        &mut self,
        binary: &Path,
        plan: &UpgradePlan,
        artifact: Option<&ReleaseArtifact>,
    ) -> anyhow::Result<ValidatedState> {
        let helper = setup_for_binary(binary, plan, artifact)?;
        let root = installation_root(plan)?;
        let bytes = run_product(
            &helper,
            plan,
            &[
                "--product".into(),
                service_product(plan)?,
                "--root".into(),
                root.to_string_lossy().into_owned(),
                "--config".into(),
                plan.config.to_string_lossy().into_owned(),
                "--json".into(),
                "check".into(),
            ],
            plan.timeout_seconds,
            self.descriptor()?,
            &self.instance_locks,
        )?;
        parse_validated_state(&bytes)
    }

    fn ready(
        &mut self,
        plan: &UpgradePlan,
        binary_sha256: &str,
        service_identity: &str,
    ) -> anyhow::Result<bool> {
        if !running_program_matches(plan, binary_sha256)? {
            return Ok(false);
        }
        let package = native_release::current_package(plan)?;
        for writer in &plan.additional_services {
            ensure!(
                package.identity.product == "xcos"
                    && writer.role == "media"
                    && writer.service == "xcos-mediamtx.service",
                "additional writer has no declared executable mapping"
            );
            let path = Path::new("bin/mediamtx");
            let file = package
                .files
                .iter()
                .find(|file| file.path == path)
                .context("verified MediaMTX executable is absent")?;
            let mut media = plan.clone();
            media.service = writer.service.clone();
            media.additional_services.clear();
            media.installed_binary = installation_root(plan)?.join(path);
            if !running_program_matches(&media, &file.sha256)? {
                return Ok(false);
            }
        }
        http_ready(plan.readiness_address, service_identity)
    }
}

fn installation_root(plan: &UpgradePlan) -> anyhow::Result<PathBuf> {
    let native = plan
        .native_release
        .as_ref()
        .context("fixed installation root is required")?;
    let root = native.root.clone();
    snapshot::require_path(&root)?;
    Ok(root)
}

fn service_product(plan: &UpgradePlan) -> anyhow::Result<String> {
    let product = plan
        .service
        .strip_suffix(".service")
        .context("service name is invalid")?;
    ensure!(
        matches!(product, "xcos" | "xczs" | "xocs" | "xscs" | "xsos" | "xszs"),
        "service does not belong to a supported product"
    );
    Ok(product.to_owned())
}

fn setup_for_binary(
    binary: &Path,
    plan: &UpgradePlan,
    artifact: Option<&ReleaseArtifact>,
) -> anyhow::Result<PathBuf> {
    if binary == native_release::installed_binary(plan)? {
        return Ok(installation_root(plan)?.join("libexec/setup"));
    }
    let artifact = artifact.context("verified target payload is missing")?;
    let entrypoint = &artifact.entrypoint;
    let helper = &artifact.setup;
    ensure!(
        helper == Path::new("libexec/setup"),
        "uncontrolled offline helper path"
    );
    let root = binary
        .ancestors()
        .nth(entrypoint.components().count())
        .context("sealed payload root cannot be resolved")?;
    ensure!(
        root.join(entrypoint) == binary,
        "entrypoint differs from verified sealed tree"
    );
    Ok(root.join(helper))
}

fn stopped_service_report(bytes: &[u8]) -> anyhow::Result<bool> {
    let value = std::str::from_utf8(bytes)?;
    let mut properties = std::collections::BTreeMap::new();
    for line in value.lines() {
        let (key, value) = line
            .split_once('=')
            .context("invalid service observation")?;
        ensure!(
            properties.insert(key, value).is_none(),
            "duplicate service observation"
        );
    }
    Ok(properties.get("LoadState") == Some(&"loaded")
        && properties.get("MainPID") == Some(&"0")
        && matches!(properties.get("ActiveState"), Some(&"inactive" | &"failed")))
}

fn http_ready(address: SocketAddr, service_identity: &str) -> anyhow::Result<bool> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut response = Vec::new();
    stream.take(16385).read_to_end(&mut response)?;
    ensure!(response.len() <= 16384, "readiness response exceeds limit");
    let response = std::str::from_utf8(&response)?;
    let (headers, body) = response
        .split_once("\r\n\r\n")
        .context("invalid readiness HTTP response")?;
    if !matches!(
        headers.lines().next(),
        Some("HTTP/1.1 200 OK" | "HTTP/1.0 200 OK")
    ) {
        return Ok(false);
    }
    let mut identities = headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.eq_ignore_ascii_case("x-service"))
        .map(|(_, value)| value.trim());
    if identities.next() != Some(service_identity) || identities.next().is_some() {
        return Ok(false);
    }
    let body: serde_json::Value = serde_json::from_str(body)?;
    Ok(body.get("ready") == Some(&serde_json::Value::Bool(true)))
}

fn running_program_matches(plan: &UpgradePlan, binary_sha256: &str) -> anyhow::Result<bool> {
    let bytes = run_bounded(
        "/usr/bin/systemctl",
        &[
            "show".into(),
            plan.service.clone(),
            "--property=MainPID".into(),
            "--property=ActiveState".into(),
        ],
        plan.timeout_seconds,
    )?;
    let value = std::str::from_utf8(&bytes)?;
    if !value.lines().any(|line| line == "ActiveState=active") {
        return Ok(false);
    }
    let pid = value
        .lines()
        .find_map(|line| line.strip_prefix("MainPID="))
        .context("service did not report MainPID")?
        .parse::<u32>()?;
    if pid == 0 {
        return Ok(false);
    }
    if fs::metadata(format!("/proc/{pid}"))?.uid() != execution::identity(plan)?.0 {
        return Ok(false);
    }
    // /proc/PID/exe is a kernel link; resolve it explicitly and then verify
    // the regular installed file. The process must run this exact release.
    let executable = fs::read_link(format!("/proc/{pid}/exe"))?;
    if executable != native_release::installed_binary(plan)?
        || snapshot::digest_file(&executable)? != binary_sha256
    {
        return Ok(false);
    }
    let mut command = Vec::new();
    fs::File::open(format!("/proc/{pid}/cmdline"))?
        .take(16385)
        .read_to_end(&mut command)?;
    ensure!(command.len() <= 16384, "running command exceeds its bound");
    let mut arguments = command.split(|byte| *byte == 0).collect::<Vec<_>>();
    if arguments.last() == Some(&&[][..]) {
        arguments.pop();
    }
    let root = installation_root(plan)?;
    let expected = if plan.service == "xcos-mediamtx.service" {
        vec![executable.clone(), root.join("config/mediamtx.yml")]
    } else {
        vec![executable.clone(), PathBuf::from("--root"), root]
    };
    if arguments
        != expected
            .iter()
            .map(|argument| argument.as_os_str().as_encoded_bytes())
            .collect::<Vec<_>>()
    {
        return Ok(false);
    }
    Ok(true)
}

pub fn read_plan(path: &Path) -> Result<UpgradePlan, UpgradeFailure> {
    let parsed = (|| -> anyhow::Result<UpgradePlan> {
        let plan = serde_json::from_slice(&snapshot::read_bounded(path, MAX_JSON)?)?;
        validate_plan(&plan)?;
        Ok(plan)
    })();
    parsed.map_err(|_| {
        failure(
            "CONTRACT_VIOLATION",
            "The upgrade plan structure, paths or permissions do not satisfy the current contract.",
            None,
        )
    })
}

fn readiness_address_allowed(address: SocketAddr, local: &[std::net::IpAddr]) -> bool {
    let ip = address.ip().to_canonical();
    address.port() > 0
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && (ip.is_loopback() || local.iter().any(|value| value.to_canonical() == ip))
}

fn validate_plan(plan: &UpgradePlan) -> anyhow::Result<()> {
    native_release::validate_plan(plan)?;
    ensure!(plan.plan_version == 1, "unsupported plan contract");
    ensure!(
        plan.service.ends_with(".service")
            && plan.service.len() <= 200
            && plan
                .service
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric()
                    || matches!(byte, b'.' | b'-' | b'_' | b'@')),
        "invalid systemd service unit"
    );
    ensure!(
        plan.timeout_seconds > 0 && plan.timeout_seconds <= 600,
        "timeout outside 1..600 seconds"
    );
    ensure!(
        plan.max_backup_bytes > 0,
        "backup byte limit must be positive"
    );
    // Explicit interface binds are valid server configurations. Probe only this
    // host, without silently redirecting a LAN-only listener to loopback.
    let local = if plan.readiness_address.ip().to_canonical().is_loopback() {
        Vec::new()
    } else {
        execution::local_ip_addresses()?
    };
    ensure!(
        readiness_address_allowed(plan.readiness_address, &local),
        "readiness must use a nonzero port on a local address"
    );
    ensure!(
        plan.additional_services.len() <= 16,
        "too many additional writers"
    );
    let mut services = BTreeSet::from([plan.service.as_str()]);
    let mut roles = BTreeSet::new();
    for entry in &plan.additional_services {
        validate_service(&entry.service)?;
        validate_service_role(&entry.role)?;
        ensure!(
            services.insert(&entry.service) && roles.insert(&entry.role),
            "duplicate writer service or role"
        );
    }
    for path in [
        &plan.target_binary,
        &plan.release_manifest,
        &plan.release_checksum,
        &plan.config,
        &plan.data_dir,
        &plan.work_directory,
    ] {
        snapshot::require_path(path)?;
    }
    if plan.native_release.is_none() {
        snapshot::require_path(&plan.installed_binary)?;
    }
    ensure!(
        plan.installed_binary != plan.target_binary,
        "target must be separate from the installed binary"
    );
    ensure!(
        !plan.resources.is_empty() && plan.resources.len() <= 128,
        "invalid resource count"
    );
    let mut names = BTreeSet::new();
    let mut primary = 0;
    let mut config = false;
    for resource in &plan.resources {
        ensure!(
            !resource.name.is_empty()
                && resource.name.len() <= 100
                && resource
                    .name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
            "invalid resource name"
        );
        ensure!(names.insert(&resource.name), "duplicate resource name");
        snapshot::require_path(&resource.path)?;
        ensure!(
            resource.path != Path::new("/"),
            "resource cannot be filesystem root"
        );
        if resource.path == plan.data_dir && resource.kind == ResourceType::Directory {
            primary += 1;
        }
        config |= resource.path == plan.config
            || (resource.kind == ResourceType::Directory
                && plan.config.starts_with(&resource.path));
        for other in [
            &plan.work_directory,
            &plan.installed_binary,
            &plan.target_binary,
            &plan.release_manifest,
            &plan.release_checksum,
        ] {
            ensure!(
                !other.starts_with(&resource.path) && !resource.path.starts_with(other),
                "upgrade inputs and backups must be outside persistent resources"
            );
        }
        for other in &plan.resources {
            if resource.name != other.name {
                ensure!(
                    !resource.path.starts_with(&other.path),
                    "persistent resources overlap"
                );
            }
        }
    }
    ensure!(
        primary == 1 && config,
        "data-dir and config must be covered exactly by persistent resources"
    );
    ensure!(
        !plan.installed_binary.starts_with(&plan.work_directory),
        "installed binary cannot be inside recovery directory"
    );
    Ok(())
}

fn validate_service_role(role: &str) -> anyhow::Result<()> {
    ensure!(
        !role.is_empty()
            && role.len() <= 64
            && role
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "invalid additional service role"
    );
    Ok(())
}
fn validate_service(service: &str) -> anyhow::Result<()> {
    ensure!(
        service.ends_with(".service")
            && service.len() <= 160
            && service
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric()
                    || matches!(byte, b'-' | b'_' | b'.' | b'@')),
        "invalid systemd service name"
    );
    Ok(())
}

fn digest_hex(bytes: impl AsRef<[u8]>) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.as_ref().len() * 2);
    for byte in bytes.as_ref() {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 15) as usize] as char);
    }
    output
}

fn validate_digest(value: &str) -> anyhow::Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid SHA-256"
    );
    Ok(())
}

pub fn verify_release(plan: &UpgradePlan) -> Result<UpgradeRelease, UpgradeFailure> {
    let verified = (|| -> anyhow::Result<UpgradeRelease> {
        validate_plan(plan)?;
        let manifest_bytes = snapshot::read_bounded(&plan.release_manifest, MAX_JSON)?;
        let checksum = snapshot::read_bounded(&plan.release_checksum, 65)?;
        native_release::verify_checksum(&manifest_bytes, &checksum)?;
        let release = native_release::package_to_release(plan, &manifest_bytes)?;
        ensure!(
            release.manifest_version == 1,
            "unsupported release contract"
        );
        release.identity.validate()?;
        release.source_identity.validate()?;
        ensure!(
            release.source_identity.product == release.identity.product
                && release.source_identity.target == release.identity.target,
            "source and target release product/target differ"
        );
        release.source_schema.validate()?;
        release.target_schema.validate()?;
        native_release::verify_input(plan, &release)?;
        validate_digest(&release.binary_sha256)?;
        ensure!(
            release.identity.target == crate::FORMAL_RELEASE_TARGET
                && cfg!(all(target_os = "linux", target_arch = "x86_64")),
            "target platform is unsupported"
        );
        ensure!(
            release.identity.product == release.source_schema.application
                && release.identity.product == release.target_schema.application,
            "schema product does not match release"
        );
        ensure!(
            snapshot::digest_file(&plan.target_binary)? == release.binary_sha256,
            "target binary checksum differs"
        );
        let mut file = snapshot::open_regular(&plan.target_binary)?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.mode() & 0o111 != 0 && metadata.mode() & 0o7022 == 0,
            "target executable has unsafe permissions"
        );
        let mut header = [0u8; 20];
        file.read_exact(&mut header)?;
        ensure!(
            header[..5] == [0x7f, b'E', b'L', b'F', 2]
                && header[5] == 1
                && header[18..20] == [0x3e, 0],
            "target is not a Linux AMD64 ELF executable"
        );
        ensure!(
            release.additional_service_roles.len() <= 16,
            "too many declared writer roles"
        );
        let mut roles = BTreeSet::new();
        for role in &release.additional_service_roles {
            validate_service_role(role)?;
            ensure!(roles.insert(role), "duplicate declared writer role");
        }
        ensure!(
            release.additional_service_roles
                == plan
                    .additional_services
                    .iter()
                    .map(|entry| entry.role.clone())
                    .collect::<Vec<_>>(),
            "plan does not cover declared additional writer roles"
        );
        let actual = plan
            .resources
            .iter()
            .map(|resource| (resource.name.as_str(), resource.kind))
            .collect::<Vec<_>>();
        let expected = release
            .resources
            .iter()
            .map(|resource| (resource.name.as_str(), resource.kind))
            .collect::<Vec<_>>();
        ensure!(
            actual == expected,
            "persistent resource coverage differs from declared product definition"
        );
        Ok(release)
    })();
    verified.map_err(|_error| {
        #[cfg(test)]
        eprintln!("verified package validation: {_error:#}");
        failure(
            "ARTIFACT_UNTRUSTED",
            "Target artifact SHA256, platform, release identity or resource definition validation failed.",
            Some(&plan.work_directory),
        )
    })
}

fn parse_validated_state(bytes: &[u8]) -> anyhow::Result<ValidatedState> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).context("product did not return JSON")?;
    let identity: SchemaIdentity = serde_json::from_value(
        value
            .get("schema_identity")
            .context("product did not report verified schema_identity")?
            .clone(),
    )?;
    identity.validate()?;
    let state_paths = serde_json::from_value(
        value
            .get("state_paths")
            .context("product did not report persistent state_paths")?
            .clone(),
    )?;
    Ok(ValidatedState {
        schema_identity: identity,
        state_paths,
    })
}

fn all_stopped(plan: &UpgradePlan, control: &mut impl ServiceControl) -> anyhow::Result<bool> {
    for service in std::iter::once(&plan.service)
        .chain(plan.additional_services.iter().map(|entry| &entry.service))
    {
        let mut observation = plan.clone();
        observation.service = service.clone();
        observation.additional_services.clear();
        if !control.is_stopped(&observation)? {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn apply(
    plan: &UpgradePlan,
    control: &mut impl ServiceControl,
) -> Result<UpgradeJournal, UpgradeFailure> {
    let release = verify_release(plan)?;
    if validate_state_transition(&release).is_err() {
        return Err(failure(
            "STATE_INCOMPATIBLE",
            "The release state contract differs from the current installation; original state was not modified.",
            Some(&plan.work_directory),
        ));
    }
    let original = native_release::installed_binary(plan).map_err(|_| {
        failure(
            "CURRENT_RELEASE_INCOMPATIBLE",
            "The current program or verified source payload identity could not be verified; maintenance was not entered.",
            None,
        )
    })?;
    control
        .verify_release_identity(&original, plan, &release.source_identity)
        .map_err(|_| {
            failure(
                "CURRENT_RELEASE_INCOMPATIBLE",
                "The installed verified package identity or declared immutable payload does not match the current baseline; maintenance was not entered.",
                None,
            )
        })?;
    let _release_upgrade = native_release::coordinate(plan, control.inherited_tool_lock()).map_err(|_| {
        failure(
            "MAINTENANCE_BUSY",
            "The fixed installation root is in use by another maintenance process or its control directory is unsafe.",
            Some(&plan.work_directory),
        )
    })?;
    if let Some(lock) = &_release_upgrade {
        control.bind_tool_lock(lock.descriptor()).map_err(|_| {
            failure(
                "MAINTENANCE_BUSY",
                "Cannot bind the installation tool lock.",
                Some(&plan.work_directory),
            )
        })?;
    }
    let mut precheck_journal = None;
    let preflight = (|| -> anyhow::Result<()> {
        PrivateStateDirectory::open_for_administration(&plan.data_dir)?;
        control.verify_service_identity(plan)?;
        snapshot::private_directory(&plan.work_directory)?;
        let installed = native_release::installed_binary(plan)?;
        let journal = UpgradeJournal {
            journal_version: 1,
            operation_id: Uuid::parse_str(
                plan.work_directory
                    .file_name()
                    .and_then(|name| name.to_str())
                    .context("operation directory UUID is missing")?,
            )?,
            phase: UpgradePhase::Prechecked,
            completed_at_micros: None,
            recovery_outcome: None,
            plan: plan.clone(),
            release,
            original_binary_sha256: snapshot::digest_file(&installed)?,
            original_binary_mode: snapshot::open_regular(&installed)?.metadata()?.mode() & 0o777,
            new_program_may_have_written: false,
            recovered_program_may_have_written: false,
            backup_complete: false,
            shared_paths: Vec::new(),
            business_paths: Vec::new(),
            runtime_locks: Vec::new(),
            backups: Vec::new(),
            native_backup: None,
            work_directory_seal: Some(execution::work_authority(plan)?),
            payload_stage_seal: None,
            startup_control: None,
        };
        precheck_journal = Some(journal);
        let journal = precheck_journal
            .as_mut()
            .context("precheck journal is missing")?;
        save(journal)?;
        execution::prepare(journal)?;
        // Persist the inode-bound staging authority before copying executable
        // payload. An interrupted precheck remains explicitly recoverable.
        save(journal)?;
        native_release::seal(journal)?;
        let staged_target = native_release::staged_binary(journal)?;
        ensure!(
            snapshot::digest_file(&staged_target)? == journal.release.binary_sha256,
            "target changed while staging"
        );
        // The verified artifact is the tool-owned deployment authority.
        // Ordinary compiled release identity is checked before any state change.
        control.verify_release_identity(&staged_target, plan, &journal.release.identity)?;
        save(journal)?;
        Ok(())
    })();
    if preflight.is_err() {
        if let Some(journal) = &mut precheck_journal
            && execution::cleanup_precheck(journal).is_ok()
        {
            journal.payload_stage_seal = None;
            let _ = transition(journal, UpgradePhase::RolledBack);
        }
        return Err(failure(
            "UPGRADE_PRECONDITION_FAILED",
            "Upgrade preflight failed; check paths, service-user permissions and existing recovery records.",
            Some(&plan.work_directory),
        ));
    }
    let mut journal = precheck_journal.ok_or_else(|| {
        failure(
            "UPGRADE_PRECONDITION_FAILED",
            "Upgrade preflight did not produce a complete journal.",
            Some(&plan.work_directory),
        )
    })?;
    let work = PrivateStateDirectory::open(&plan.work_directory).map_err(|_| {
        failure(
            "UPGRADE_PRECONDITION_FAILED",
            "The upgrade-journal directory could not be acquired.",
            Some(&plan.work_directory),
        )
    })?;
    let _coordinator = work.try_maintenance_lock().map_err(|_| {
        failure(
            "MAINTENANCE_BUSY",
            "Another maintenance process is using this upgrade journal.",
            Some(&plan.work_directory),
        )
    })?;
    let result = apply_inner(&mut journal, control);
    control.release_instance_locks();
    result.map_err(|error| {
        let code = match error.downcast_ref::<StructureFailure>() {
            Some(StructureFailure::Incompatible) => "STATE_INCOMPATIBLE",
            Some(StructureFailure::Validation) => "UPGRADE_STATE_VALIDATION_FAILED",
            Some(StructureFailure::ResourceCoverage) => "UPGRADE_RESOURCE_COVERAGE_FAILED",
            None => "UPGRADE_EXECUTION_FAILED",
        };
        failure(code, format!("Upgrade interrupted during {:?}. The service remains in an explicit maintenance or potentially writable state; use inspect-upgrade and recover-upgrade.", journal.phase), Some(&plan.work_directory))
    })?;
    Ok(journal)
}

fn apply_inner(
    journal: &mut UpgradeJournal,
    control: &mut impl ServiceControl,
) -> anyhow::Result<()> {
    transition(journal, UpgradePhase::MaintenanceIntent)?;
    control.establish_startup_control(journal)?;
    control.stop(journal)?;
    control.verify_startup_control(journal)?;
    ensure!(
        all_stopped(&journal.plan, control)?,
        "service remains active"
    );
    let state = PrivateStateDirectory::open_for_administration(&journal.plan.data_dir)?;
    ensure!(
        all_stopped(&journal.plan, control)?,
        "service restarted during maintenance acquisition"
    );
    transition(journal, UpgradePhase::MaintenanceAcquired)?;
    ensure!(
        snapshot::digest_file(&native_release::installed_binary(&journal.plan)?)?
            == journal.original_binary_sha256,
        "installed binary changed since precheck"
    );
    let configuration = control.configuration(
        &native_release::installed_binary(&journal.plan)?,
        &journal.plan,
        journal.release.artifact.as_ref(),
    )?;
    let root = installation_root(&journal.plan)?;
    if configuration.get("root") != Some(&serde_json::to_value(&root)?)
        || configuration.get("product")
            != Some(&serde_json::to_value(&journal.release.identity.product)?)
        || configuration.get("data_dir") != Some(&serde_json::to_value(&journal.plan.data_dir)?)
        || journal.plan.config != root.join("config/config.json")
    {
        return Err(StructureFailure::ResourceCoverage.into());
    }
    let declared: Vec<PathBuf> = serde_json::from_value(
        configuration
            .get("state_paths")
            .context("configuration does not declare state roots")?
            .clone(),
    )?;
    validate_coverage(&declared, &journal.plan)?;
    journal.shared_paths = serde_json::from_value(
        configuration
            .get("shared_paths")
            .context("configuration does not declare shared roots")?
            .clone(),
    )?;
    validate_shared_policy(
        &journal.shared_paths,
        &journal.plan,
        &journal.release.identity.product,
    )?;
    journal.business_paths = serde_json::from_value(
        configuration
            .get("business_paths")
            .context("configuration lacks business roots")?
            .clone(),
    )?;
    let lock_paths: Vec<runtime_locks::Declaration> = serde_json::from_value(
        configuration
            .get("runtime_locks")
            .context("configuration lacks runtime locks")?
            .clone(),
    )?;
    let held = runtime_locks::acquire(
        &journal.plan,
        &lock_paths,
        &journal.business_paths,
        &journal.runtime_locks,
    )?;
    journal.runtime_locks = held.iter().map(|lock| lock.authority.clone()).collect();
    control.bind_instance_locks(
        &held
            .iter()
            .map(|lock| {
                use std::os::fd::AsFd;
                (lock.authority.path.clone(), lock.file.as_fd())
            })
            .collect::<Vec<_>>(),
    )?;
    save(journal)?;
    transition(journal, UpgradePhase::BackupStarted)?;
    snapshot::copy_regular(
        &native_release::installed_binary(&journal.plan)?,
        &journal.plan.work_directory.join("original-binary"),
        journal.original_binary_mode,
    )?;
    let mut backup_bytes =
        snapshot::open_regular(&native_release::installed_binary(&journal.plan)?)?
            .metadata()?
            .len();
    backup_bytes = backup_bytes
        .checked_add(native_release::backup_original(journal)?)
        .context("complete backup size overflow")?;
    ensure!(
        backup_bytes <= journal.plan.max_backup_bytes,
        "complete backup exceeds declared byte limit"
    );
    for (index, resource) in journal.plan.resources.iter().enumerate() {
        runtime_locks::verify(&held)?;
        let primary = resource.path == journal.plan.data_dir;
        let entries = resource_inventory(journal, resource, &resource.path, primary)?;
        for entry in &entries {
            backup_bytes = backup_bytes
                .checked_add(entry.bytes)
                .context("backup size overflow")?;
        }
        ensure!(
            backup_bytes <= journal.plan.max_backup_bytes,
            "complete backup exceeds declared byte limit"
        );
        snapshot::snapshot(
            &resource.path,
            &journal
                .plan
                .work_directory
                .join(format!("resource-{index}")),
            &entries,
        )?;
        ensure!(
            entries == resource_inventory(journal, resource, &resource.path, primary)?,
            "state changed during backup"
        );
        journal.backups.push(ResourceBackup {
            resource: resource.clone(),
            ownership: snapshot::ownership(&resource.path, &entries)?,
            entries,
        });
    }
    ensure!(
        all_stopped(&journal.plan, control)?,
        "a state writer restarted during backup"
    );
    journal.backup_complete = true;
    transition(journal, UpgradePhase::BackupComplete)?;
    verify_backups(journal)?;
    // Both products validate their exact current contract without writes.
    let staged_target = native_release::staged_binary(journal)?;
    native_release::verify_sealed(journal)?;
    ensure!(
        snapshot::digest_file(&staged_target)? == journal.release.binary_sha256,
        "sealed target changed"
    );
    let source = control
        .validate(
            &native_release::installed_binary(&journal.plan)?,
            &journal.plan,
            journal.release.artifact.as_ref(),
        )
        .map_err(|_| StructureFailure::Validation)?;
    if source.schema_identity != journal.release.source_schema {
        return Err(StructureFailure::Incompatible.into());
    }
    validate_coverage(&source.state_paths, &journal.plan)?;
    verify_unchanged(journal).map_err(|_| StructureFailure::Validation)?;
    let before_validation = inventory_current(journal)?;
    let target = control
        .validate(
            &staged_target,
            &journal.plan,
            journal.release.artifact.as_ref(),
        )
        .map_err(|_| StructureFailure::Validation)?;
    if target.schema_identity != journal.release.target_schema {
        return Err(StructureFailure::Validation.into());
    }
    validate_coverage(&target.state_paths, &journal.plan)?;
    verify_unchanged(journal).map_err(|_| StructureFailure::Validation)?;
    if before_validation != inventory_current(journal)? {
        return Err(StructureFailure::Validation.into());
    }
    ensure!(
        all_stopped(&journal.plan, control)?,
        "a state writer restarted during validation"
    );
    transition(journal, UpgradePhase::Validated)?;
    state.verify_identity()?;
    runtime_locks::verify(&held)?;
    transition(journal, UpgradePhase::SwitchIntent)?;
    native_release::install_target(journal)?;
    transition(journal, UpgradePhase::Switched)?;
    // Persist possible writes before handing execution to the service manager.
    journal.new_program_may_have_written = true;
    transition(journal, UpgradePhase::StartIntent)?;
    runtime_locks::verify(&held)?;
    control.release_instance_locks();
    drop(held);
    control.release_startup_control(journal)?;
    control.start(&journal.plan)?;
    wait_ready(journal, control, &journal.release.binary_sha256)?;
    transition(journal, UpgradePhase::Ready)
}

fn validate_coverage(paths: &[PathBuf], plan: &UpgradePlan) -> anyhow::Result<()> {
    if paths.is_empty() || paths.len() > 1024 {
        return Err(StructureFailure::ResourceCoverage.into());
    }
    for path in paths {
        if snapshot::require_path(path).is_err()
            || !plan.resources.iter().any(|resource| {
                path == &resource.path
                    || (resource.kind == ResourceType::Directory
                        && path.starts_with(&resource.path))
            })
        {
            return Err(StructureFailure::ResourceCoverage.into());
        }
    }
    // A plan must not broaden a declared helper's data roots or add unrelated
    // protected directories. Normalize nested declarations before matching;
    // the install's fixed configuration file is the only implicit resource.
    let mut declared = paths.to_vec();
    if !declared.contains(&plan.config) {
        declared.push(plan.config.clone());
    }
    declared.sort_by_key(|path| (path.components().count(), path.clone()));
    declared.dedup();
    let mut minimal = Vec::<PathBuf>::new();
    for path in declared {
        if !minimal
            .iter()
            .any(|parent| parent.is_dir() && path.starts_with(parent))
        {
            minimal.push(path);
        }
    }
    if plan.resources.len() != minimal.len()
        || plan.resources.iter().any(|resource| {
            !minimal.contains(&resource.path)
                || match resource.kind {
                    ResourceType::File => !resource.path.is_file(),
                    ResourceType::Directory => !resource.path.is_dir(),
                }
        })
    {
        return Err(StructureFailure::ResourceCoverage.into());
    }
    Ok(())
}

fn validate_shared_policy(
    paths: &[PathBuf],
    plan: &UpgradePlan,
    product: &str,
) -> anyhow::Result<()> {
    ensure!(paths.len() <= 16, "too many shared roots");
    ensure!(
        paths.is_empty() || product == "xczs",
        "product does not declare shared file ownership"
    );
    let mut unique = BTreeSet::new();
    let configuration = installation_root(plan)?.join("config");
    let logs = installation_root(plan)?.join("logs");
    for path in paths {
        snapshot::require_path(path)?;
        ensure!(unique.insert(path), "duplicate shared root");
        ensure!(
            plan.resources
                .iter()
                .any(|resource| resource.path == *path && resource.kind == ResourceType::Directory),
            "shared root is not an exact protected directory"
        );
        ensure!(
            !path.starts_with(&plan.data_dir)
                && !plan.data_dir.starts_with(path)
                && !path.starts_with(&configuration)
                && !configuration.starts_with(path)
                && !path.starts_with(&logs)
                && !logs.starts_with(path),
            "shared data cannot relax private state or configuration"
        );
    }
    Ok(())
}

fn resource_inventory(
    journal: &UpgradeJournal,
    resource: &PersistentResource,
    path: &Path,
    primary: bool,
) -> anyhow::Result<Vec<Entry>> {
    let excluded = if path == resource.path {
        runtime_locks::file_paths(&journal.runtime_locks)
    } else {
        Vec::new()
    };
    snapshot::inventory_preserving(
        path,
        resource.kind == ResourceType::Directory,
        journal.plan.max_backup_bytes,
        primary,
        journal.shared_paths.contains(&resource.path),
        &excluded,
    )
}

fn wait_ready(
    journal: &UpgradeJournal,
    control: &mut impl ServiceControl,
    digest: &str,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(journal.plan.timeout_seconds);
    loop {
        let ready = control.ready(&journal.plan, digest, &journal.release.identity.product);
        if ready.unwrap_or(false) {
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "service did not become business-ready before the deadline"
        );
        thread::sleep(Duration::from_millis(200));
    }
}

fn save(journal: &UpgradeJournal) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(journal)?;
    ensure!(
        bytes.len() as u64 <= MAX_JOURNAL,
        "upgrade journal exceeds limit"
    );
    snapshot::atomic_json(&journal.plan.work_directory.join(JOURNAL), journal)
}

fn transition(journal: &mut UpgradeJournal, phase: UpgradePhase) -> anyhow::Result<()> {
    journal.phase = phase;
    journal.completed_at_micros = if matches!(phase, UpgradePhase::Ready | UpgradePhase::RolledBack)
    {
        Some(u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_micros(),
        )?)
    } else {
        None
    };
    save(journal)?;
    xcsc::log::LogRecord::client(
        "xssc",
        "maintenance",
        "xssc.phase_changed",
        "Upgrade phase changed.",
        xcsc::log::Level::Info,
    )?
    .with_task_id(&journal.operation_id.to_string())?
    .with_attribute("phase", serde_json::to_value(phase)?)?
    .with_attribute("product", journal.release.identity.product.clone())?
    .emit_stderr()?;
    Ok(())
}

fn verify_backups(journal: &UpgradeJournal) -> anyhow::Result<()> {
    native_release::verify_original_backup(journal)?;
    ensure!(
        journal.backup_complete && journal.backups.len() == journal.plan.resources.len(),
        "recoverable backup is incomplete"
    );
    ensure!(
        snapshot::digest_file(&journal.plan.work_directory.join("original-binary"))?
            == journal.original_binary_sha256,
        "original binary backup differs"
    );
    for (index, backup) in journal.backups.iter().enumerate() {
        ensure!(
            backup.resource == journal.plan.resources[index],
            "backup mapping differs"
        );
        snapshot::validate_ownership(&backup.entries, &backup.ownership)?;
        let path = journal
            .plan
            .work_directory
            .join(format!("resource-{index}"));
        ensure!(
            resource_inventory(journal, &backup.resource, &path, false)? == backup.entries,
            "backup inventory differs"
        );
    }
    Ok(())
}

fn inventory_current(journal: &UpgradeJournal) -> anyhow::Result<Vec<Vec<Entry>>> {
    journal
        .plan
        .resources
        .iter()
        .map(|resource| {
            resource_inventory(
                journal,
                resource,
                &resource.path,
                resource.path == journal.plan.data_dir,
            )
        })
        .collect()
}

fn verify_unchanged(journal: &UpgradeJournal) -> anyhow::Result<()> {
    for backup in &journal.backups {
        let current = snapshot::ownership(&backup.resource.path, &backup.entries)?;
        ensure!(
            current == backup.ownership,
            "state ownership, ACL or modification time changed"
        );
        ensure!(
            resource_inventory(
                journal,
                &backup.resource,
                &backup.resource.path,
                backup.resource.path == journal.plan.data_dir
            )? == backup.entries,
            "validator or another writer modified state"
        );
    }
    Ok(())
}

pub fn inspect(work_directory: &Path) -> Result<UpgradeJournal, UpgradeFailure> {
    let inspected = (|| -> anyhow::Result<UpgradeJournal> {
        PrivateStateDirectory::open(work_directory)?;
        let journal: UpgradeJournal = serde_json::from_slice(&snapshot::read_bounded(
            &work_directory.join(JOURNAL),
            MAX_JOURNAL,
        )?)?;
        ensure!(
            journal.journal_version == 1 && journal.plan.work_directory == work_directory,
            "journal identity differs"
        );
        validate_plan(&journal.plan)?;
        ensure!(
            work_directory
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| journal.operation_id.to_string() == name),
            "journal operation does not match its canonical work directory"
        );
        validate_shared_policy(
            &journal.shared_paths,
            &journal.plan,
            &journal.release.identity.product,
        )?;
        if journal.phase == UpgradePhase::Prechecked {
            execution::verify_precheck(&journal)?;
        } else {
            execution::verify(&journal)?;
        }
        native_release::validate_artifact(&journal.plan, &journal.release)?;
        ensure!(
            journal.native_backup.is_some()
                || matches!(
                    journal.phase,
                    UpgradePhase::Prechecked | UpgradePhase::RolledBack
                ),
            "native journal mapping differs"
        );
        validate_digest(&journal.original_binary_sha256)?;
        validate_digest(&journal.release.binary_sha256)?;
        journal.release.identity.validate()?;
        ensure!(
            journal.release.additional_service_roles
                == journal
                    .plan
                    .additional_services
                    .iter()
                    .map(|entry| entry.role.clone())
                    .collect::<Vec<_>>(),
            "journal additional writer mapping differs from verified release"
        );
        journal.release.source_identity.validate()?;
        ensure!(
            journal.release.source_identity.product == journal.release.identity.product
                && journal.release.source_identity.target == journal.release.identity.target,
            "journal source release authority differs"
        );
        journal.release.source_schema.validate()?;
        journal.release.target_schema.validate()?;
        validate_state_transition(&journal.release)?;
        ensure!(
            !matches!(
                journal.phase,
                UpgradePhase::StartIntent | UpgradePhase::Ready
            ) || journal.new_program_may_have_written,
            "journal handoff evidence is inconsistent"
        );
        ensure!(
            journal.phase != UpgradePhase::RecoveryStartIntent
                || journal.recovered_program_may_have_written,
            "recovery handoff evidence is inconsistent"
        );
        ensure!(
            !matches!(
                journal.phase,
                UpgradePhase::Validated
                    | UpgradePhase::SwitchIntent
                    | UpgradePhase::Switched
                    | UpgradePhase::StartIntent
                    | UpgradePhase::Ready
                    | UpgradePhase::RecoveryRestoring
            ) || journal.backup_complete,
            "journal backup evidence is inconsistent"
        );
        ensure!(
            journal.original_binary_mode & 0o111 != 0 && journal.original_binary_mode & !0o777 == 0,
            "unsafe original binary mode"
        );
        if journal.backup_complete {
            verify_backups(&journal)?;
        }
        Ok(journal)
    })();
    inspected.map_err(|_| {
        failure(
            "RECOVERY_STATE_INVALID",
            "Upgrade-journal, backup or directory-identity validation failed; recovery was not performed.",
            Some(work_directory),
        )
    })
}

/// Combine durable intent with actual binary and persistent-state observations.
/// An unreadable resource is uncertainty, never proof that no writes occurred.
pub fn inspect_status(work_directory: &Path) -> Result<UpgradeInspection, UpgradeFailure> {
    let journal = inspect(work_directory)?;
    let installed_binary_sha256 = native_release::installed_binary(&journal.plan)
        .ok()
        .and_then(|path| snapshot::digest_file(&path).ok());
    let installed_program = native_release::program_status(&journal).unwrap_or("unreadable");
    let persistent_state_verification = if !journal.backup_complete {
        "no-complete-backup"
    } else if verify_unchanged(&journal).is_ok() {
        "matches-backup"
    } else {
        "changed-or-unreadable"
    };
    Ok(UpgradeInspection {
        journal,
        installed_program,
        installed_binary_sha256,
        persistent_state_verification,
    })
}

/// Recover into the original, verified program/configuration/data combination.
/// After handoff, callers must explicitly authorize restoring the pre-upgrade
/// snapshot and losing any subsequent writes. No automatic retry restarts the
/// upgrade or claims that an observation timeout proves no writes occurred.
pub fn recover(
    work_directory: &Path,
    allow_data_loss: bool,
    control: &mut impl ServiceControl,
) -> Result<UpgradeJournal, UpgradeFailure> {
    let mut journal = inspect(work_directory)?;
    let _release_upgrade = native_release::coordinate(&journal.plan, control.inherited_tool_lock()).map_err(|_| {
        failure(
            "MAINTENANCE_BUSY",
            "The release directory is in use by another maintenance process, or the directory is unsafe.",
            Some(work_directory),
        )
    })?;
    if let Some(lock) = &_release_upgrade {
        control.bind_tool_lock(lock.descriptor()).map_err(|_| {
            failure(
                "MAINTENANCE_BUSY",
                "Cannot bind the installation tool lock.",
                Some(work_directory),
            )
        })?;
    }
    if journal.phase == UpgradePhase::RolledBack {
        return Ok(journal);
    }
    if (journal.new_program_may_have_written || journal.recovered_program_may_have_written)
        && !allow_data_loss
    {
        return Err(failure(
            "RECOVERY_AUTHORIZATION_REQUIRED",
            "Runtime ownership has been transferred to the target program, which may have received new business writes. Restoring the old backup discards those writes; use --allow-data-loss only with explicit authorization.",
            Some(work_directory),
        ));
    }
    let work = PrivateStateDirectory::open(work_directory).map_err(|_| {
        failure(
            "RECOVERY_STATE_INVALID",
            "The recovery directory could not be acquired.",
            Some(work_directory),
        )
    })?;
    let _coordinator = work.try_maintenance_lock().map_err(|_| {
        failure(
            "MAINTENANCE_BUSY",
            "Another maintenance process is using this recovery journal.",
            Some(work_directory),
        )
    })?;
    let result = (|| -> anyhow::Result<()> {
        // Prechecked has no resource changes; close its record without
        // changing a service that the operator may have subsequently started.
        if journal.phase == UpgradePhase::Prechecked {
            ensure!(
                snapshot::digest_file(&native_release::installed_binary(&journal.plan)?)?
                    == journal.original_binary_sha256,
                "installed binary differs from the precheck"
            );
            execution::cleanup_precheck(&journal)?;
            journal.payload_stage_seal = None;
            return transition(&mut journal, UpgradePhase::RolledBack);
        }
        transition(&mut journal, UpgradePhase::RecoveryMaintenanceIntent)?;
        control.establish_startup_control(&mut journal)?;
        control.stop(&mut journal)?;
        control.verify_startup_control(&journal)?;
        ensure!(
            all_stopped(&journal.plan, control)?,
            "service remains active during recovery"
        );
        let state = PrivateStateDirectory::open_for_administration(&journal.plan.data_dir)?;
        ensure!(
            all_stopped(&journal.plan, control)?,
            "service restarted during recovery maintenance acquisition"
        );
        let paths = if journal.runtime_locks.is_empty() {
            let config = control.configuration(
                &native_release::installed_binary(&journal.plan)?,
                &journal.plan,
                journal.release.artifact.as_ref(),
            )?;
            journal.business_paths = serde_json::from_value(
                config
                    .get("business_paths")
                    .context("configuration lacks business roots")?
                    .clone(),
            )?;
            serde_json::from_value(
                config
                    .get("runtime_locks")
                    .context("configuration lacks runtime locks")?
                    .clone(),
            )?
        } else {
            runtime_locks::declarations(&journal.runtime_locks)
        };
        let held = runtime_locks::acquire(
            &journal.plan,
            &paths,
            &journal.business_paths,
            &journal.runtime_locks,
        )?;
        journal.runtime_locks = held.iter().map(|lock| lock.authority.clone()).collect();
        control.bind_instance_locks(
            &held
                .iter()
                .map(|lock| {
                    use std::os::fd::AsFd;
                    (lock.authority.path.clone(), lock.file.as_fd())
                })
                .collect::<Vec<_>>(),
        )?;
        save(&journal)?;
        let installed = snapshot::digest_file(&native_release::installed_binary(&journal.plan)?);
        ensure!(
            installed
                .as_ref()
                .is_ok_and(|value| value == &journal.original_binary_sha256
                    || value == &journal.release.binary_sha256)
                || (installed.is_err() && native_release::permitted_missing_original(&journal)?),
            "installed binary has an unknown identity; recovery refuses to overwrite it"
        );
        if journal.backup_complete {
            verify_backups(&journal)?;
            transition(&mut journal, UpgradePhase::RecoveryRestoring)?;
            if native_release::original_needs_repair(&journal)? {
                journal
                    .native_backup
                    .as_mut()
                    .context("native repair mapping missing")?
                    .source_recovery_started = true;
                save(&journal)?;
            }
            for (index, backup) in journal.backups.iter().enumerate() {
                runtime_locks::verify(&held)?;
                snapshot::restore_preserving(
                    &work_directory.join(format!("resource-{index}")),
                    &backup.resource.path,
                    &backup.entries,
                    u64::MAX,
                    &backup.ownership,
                    journal.shared_paths.contains(&backup.resource.path),
                    snapshot::Preserved {
                        files: &runtime_locks::file_paths(&journal.runtime_locks),
                        directories: &runtime_locks::directory_paths(&journal.runtime_locks),
                    },
                )?;
                runtime_locks::verify(&held)?;
                snapshot::restore_ownership(
                    &backup.resource.path,
                    &backup.entries,
                    &backup.ownership,
                )?;
            }
            native_release::restore_original(&journal)?;
            verify_unchanged(&journal)?;
            let before_validation = inventory_current(&journal)?;
            let restored = control.validate(
                &native_release::installed_binary(&journal.plan)?,
                &journal.plan,
                journal.release.artifact.as_ref(),
            )?;
            ensure!(
                restored.schema_identity == journal.release.source_schema,
                "restored current structure differs from the original contract"
            );
            validate_coverage(&restored.state_paths, &journal.plan)?;
            verify_unchanged(&journal)?;
            ensure!(
                before_validation == inventory_current(&journal)?,
                "restored current validator wrote protected state"
            );
        } else {
            // No snapshot was marked complete, so the tool has not executed a
            // validator or switched a binary. Never use a partial backup.
            ensure!(
                snapshot::digest_file(&native_release::installed_binary(&journal.plan)?)?
                    == journal.original_binary_sha256,
                "binary changed before backup completed"
            );
        }
        state.verify_identity()?;
        journal.recovered_program_may_have_written = true;
        transition(&mut journal, UpgradePhase::RecoveryStartIntent)?;
        runtime_locks::verify(&held)?;
        control.release_instance_locks();
        drop(held);
        control.release_startup_control(&mut journal)?;
        let outcome = control.start_recovered(&journal)?;
        journal.recovery_outcome = Some(outcome.into());
        save(&journal)?;
        if outcome == "restored-ready-required" {
            wait_ready(&journal, control, &journal.original_binary_sha256)?;
        }
        transition(&mut journal, UpgradePhase::RolledBack)
    })();
    control.release_instance_locks();
    result.map_err(|_error| {
        failure(
            "RECOVERY_EXECUTION_FAILED",
            format!("Recovery interrupted during {:?}. The original journal and backups were preserved.", journal.phase),
            Some(work_directory),
        )
    })?;
    Ok(journal)
}

/// CLI observations coordinate the complete managed installation before reading state.
pub fn inspect_coordinated(
    work: &Path,
    control: &mut impl ServiceControl,
) -> anyhow::Result<UpgradeInspection> {
    snapshot::require_path(work)?;
    let upgrades = work.parent().context("operation parent missing")?;
    let maintenance = upgrades.parent().context("maintenance parent missing")?;
    ensure!(
        upgrades.file_name() == Some(std::ffi::OsStr::new("upgrades"))
            && maintenance.file_name() == Some(std::ffi::OsStr::new("maintenance")),
        "operation is outside fixed maintenance scope"
    );
    let root = maintenance.parent().context("installation root missing")?;
    let lock = native_release::coordinate_root(root, control.inherited_tool_lock())?;
    control.bind_tool_lock(lock.descriptor())?;
    Ok(inspect_status(work)?)
}
