//! Offline upgrade orchestration. Product code owns read-only current-state
//! validation; this module owns maintenance, snapshots, release switching and
//! interruption recovery. No server runtime links this module.

mod execution;
mod native_release;
mod process;
#[cfg(test)]
mod product_tests;
mod snapshot;
pub use native_release::{NativeReleasePlan, ReleaseArtifact};
#[cfg(test)]
mod tests;

use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, ensure};
use process::{run_bounded, run_product, run_product_diagnostic};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snapshot::{Entry, PENDING};
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

/// Signed as exact JSON bytes with an independently trusted Ed25519 key.
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
    ensure!(
        release.source_schema == release.target_schema,
        "a future structure change requires its own version's explicit implementation"
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
    pub release_signature: PathBuf,
    pub trusted_public_key: PathBuf,
    /// DER SHA-256 obtained independently of the downloaded release bundle.
    pub trusted_public_key_sha256: String,
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
    pub operation_id: Uuid,
    pub phase: UpgradePhase,
    pub plan: UpgradePlan,
    pub release: UpgradeRelease,
    pub original_binary_sha256: String,
    pub original_binary_mode: u32,
    /// Set before releasing maintenance, so a crash cannot assert absence of
    /// writes simply because the start command or readiness observation failed.
    pub new_program_may_have_written: bool,
    pub recovered_program_may_have_written: bool,
    pub backup_complete: bool,
    backups: Vec<ResourceBackup>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    native_backup: Option<native_release::NativeBackup>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    execution_seal: Option<execution::ExecutionSeal>,
}

#[derive(Clone, Debug, Serialize)]
pub struct UpgradeFailure {
    pub code: &'static str,
    pub message: String,
    pub work_directory: Option<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
enum StructureFailure {
    #[error("Existing data structure does not match the signed current-source structure")]
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
    pub maintenance_pending: bool,
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
    fn is_stopped(&mut self, plan: &UpgradePlan) -> anyhow::Result<bool>;
    fn start(&mut self, plan: &UpgradePlan) -> anyhow::Result<()>;
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
pub struct SystemdControl;

impl ServiceControl for SystemdControl {
    fn verify_release_identity(
        &mut self,
        binary: &Path,
        plan: &UpgradePlan,
        expected: &ReleaseIdentity,
    ) -> anyhow::Result<()> {
        let bytes = run_product(
            binary,
            plan,
            &["release-identity".into(), "--json".into()],
            plan.timeout_seconds,
        )?;
        let identity: ReleaseIdentity = serde_json::from_slice(&bytes)?;
        identity.validate()?;
        ensure!(
            identity == *expected,
            "compiled release identity differs from signed authority"
        );
        Ok(())
    }
    fn verify_service_identity(&mut self, plan: &UpgradePlan) -> anyhow::Result<()> {
        execution::verify_service(plan)
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

    fn validate(
        &mut self,
        binary: &Path,
        plan: &UpgradePlan,
        artifact: Option<&ReleaseArtifact>,
    ) -> anyhow::Result<ValidatedState> {
        let environment = native_release::diagnostic_environment(binary, artifact)?;
        let bytes = run_product_diagnostic(
            binary,
            plan,
            &[
                "config".into(),
                "validate".into(),
                "--config".into(),
                plan.config.to_string_lossy().into_owned(),
                "--data-dir".into(),
                plan.data_dir.to_string_lossy().into_owned(),
                "--json".into(),
            ],
            plan.timeout_seconds,
            environment
                .as_ref()
                .map(|(name, root)| (name.as_str(), root.as_path())),
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
        http_ready(plan.readiness_address, service_identity)
    }
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
    ensure!(
        plan.readiness_address.ip().is_loopback() && plan.readiness_address.port() > 0,
        "readiness must use an explicit loopback address"
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
    validate_digest(&plan.trusted_public_key_sha256)?;
    for path in [
        &plan.target_binary,
        &plan.release_manifest,
        &plan.release_signature,
        &plan.trusted_public_key,
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
            &plan.release_signature,
            &plan.trusted_public_key,
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
        let signature = snapshot::read_bounded(&plan.release_signature, 64)?;
        ensure!(signature.len() == 64, "signature must be Ed25519");
        // Convert the public key before comparing its independently pinned DER
        // fingerprint. A bundle's self-declared hash is never the trust anchor.
        let key_bytes = snapshot::read_bounded(&plan.trusted_public_key, 8192)?;
        let key = tempfile::NamedTempFile::new()?;
        fs::write(key.path(), key_bytes)?;
        let der = run_bounded(
            "/usr/bin/openssl",
            &[
                "pkey".into(),
                "-pubin".into(),
                "-in".into(),
                key.path().to_string_lossy().into_owned(),
                "-outform".into(),
                "DER".into(),
            ],
            plan.timeout_seconds,
        )?;
        ensure!(
            digest_hex(Sha256::digest(&der)) == plan.trusted_public_key_sha256,
            "trusted public key fingerprint differs"
        );
        // Ed25519 SubjectPublicKeyInfo has a fixed 12-byte prefix and 32-byte key.
        ensure!(
            der.len() == 44
                && der[..12]
                    == [
                        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
                    ],
            "only Ed25519 release keys are supported"
        );
        let manifest = tempfile::NamedTempFile::new()?;
        fs::write(manifest.path(), &manifest_bytes)?;
        let detached = tempfile::NamedTempFile::new()?;
        fs::write(detached.path(), signature)?;
        run_bounded(
            "/usr/bin/openssl",
            &[
                "pkeyutl".into(),
                "-verify".into(),
                "-pubin".into(),
                "-inkey".into(),
                key.path().to_string_lossy().into_owned(),
                "-rawin".into(),
                "-in".into(),
                manifest.path().to_string_lossy().into_owned(),
                "-sigfile".into(),
                detached.path().to_string_lossy().into_owned(),
            ],
            plan.timeout_seconds,
        )?;
        let release: UpgradeRelease = serde_json::from_slice(&manifest_bytes)?;
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
            "too many signed writer roles"
        );
        let mut roles = BTreeSet::new();
        for role in &release.additional_service_roles {
            validate_service_role(role)?;
            ensure!(roles.insert(role), "duplicate signed writer role");
        }
        ensure!(
            release.additional_service_roles
                == plan
                    .additional_services
                    .iter()
                    .map(|entry| entry.role.clone())
                    .collect::<Vec<_>>(),
            "plan does not cover signed additional writer roles"
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
            "persistent resource coverage differs from signed product definition"
        );
        Ok(release)
    })();
    verified.map_err(|_| {
        failure(
            "ARTIFACT_UNTRUSTED",
            "Target artifact signature, trust anchor, platform, release identity or resource definition validation failed.",
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
fn require_stopped(
    plan: &UpgradePlan,
    control: &mut impl ServiceControl,
) -> Result<(), UpgradeFailure> {
    if !all_stopped(plan, control).unwrap_or(false) {
        return Err(failure(
            "SERVER_MUST_BE_STOPPED",
            "Services or related data writers have not been confirmed stopped. Stop all declared instances and disable automatic restart by other managers before running offline maintenance; this tool does not stop services.",
            Some(&plan.work_directory),
        ));
    }
    Ok(())
}

pub fn apply(
    plan: &UpgradePlan,
    control: &mut impl ServiceControl,
) -> Result<UpgradeJournal, UpgradeFailure> {
    let release = verify_release(plan)?;
    if validate_state_transition(&release).is_err() {
        return Err(failure(
            "STATE_INCOMPATIBLE",
            "This future release changes the state contract without providing an explicit conversion for that version; original state was not modified.",
            Some(&plan.work_directory),
        ));
    }
    require_stopped(plan, control)?;
    let original = native_release::installed_binary(plan).map_err(|_| {
        failure(
            "CURRENT_RELEASE_INCOMPATIBLE",
            "The current program or complete release-directory identity could not be verified; maintenance was not entered.",
            None,
        )
    })?;
    control
        .verify_release_identity(&original, plan, &release.source_identity)
        .map_err(|_| {
            failure(
                "CURRENT_RELEASE_INCOMPATIBLE",
                "The current program compiled release identity does not match the signed current baseline; maintenance was not entered.",
                None,
            )
        })?;
    let _instance_upgrade = coordinator_lock(&plan.data_dir).map_err(|_| {
        failure(
            "MAINTENANCE_BUSY",
            "Another upgrade process is maintaining this data directory.",
            Some(&plan.work_directory),
        )
    })?;
    let _release_upgrade = native_release::coordinate(plan).map_err(|_| {
        failure(
            "MAINTENANCE_BUSY",
            "The release directory is in use by another maintenance process, or the selector directory is unsafe.",
            Some(&plan.work_directory),
        )
    })?;
    let mut journal = (|| -> anyhow::Result<UpgradeJournal> {
        ensure!(
            !plan.data_dir.join(PENDING).exists(),
            "another interrupted upgrade is pending"
        );
        PrivateStateDirectory::open_for_administration(&plan.data_dir)?;
        control.verify_service_identity(plan)?;
        snapshot::private_directory(&plan.work_directory)?;
        let installed = native_release::installed_binary(plan)?;
        let mut journal = UpgradeJournal {
            journal_version: 1,
            operation_id: Uuid::new_v4(),
            phase: UpgradePhase::Prechecked,
            plan: plan.clone(),
            release,
            original_binary_sha256: snapshot::digest_file(&installed)?,
            original_binary_mode: snapshot::open_regular(&installed)?.metadata()?.mode() & 0o777,
            new_program_may_have_written: false,
            recovered_program_may_have_written: false,
            backup_complete: false,
            backups: Vec::new(),
            native_backup: None,
            execution_seal: None,
        };
        execution::prepare(&mut journal)?;
        if journal.release.artifact.is_some() {
            native_release::seal(&mut journal)?;
        } else {
            snapshot::copy_regular(
                &plan.target_binary,
                &native_release::staged_binary(&journal)?,
                if journal.execution_seal.is_some() {
                    0o555
                } else {
                    0o500
                },
            )?;
        }
        let staged_target = native_release::staged_binary(&journal)?;
        ensure!(
            snapshot::digest_file(&staged_target)? == journal.release.binary_sha256,
            "target changed while staging"
        );
        // The signed artifact is the tool-owned deployment authority.
        // Ordinary compiled release identity is checked before any state change.
        control.verify_release_identity(&staged_target, plan, &journal.release.identity)?;
        save(&journal)?;
        Ok(journal)
    })()
    .map_err(|_| {
        failure(
            "UPGRADE_PRECONDITION_FAILED",
            "Upgrade preflight failed; check paths, service-user permissions and existing recovery records.",
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

struct StateLock {
    file: xcsc::state_file::SecureStateFile,
}

impl StateLock {
    fn acquire(file: xcsc::state_file::SecureStateFile) -> anyhow::Result<Self> {
        rustix::fs::flock(
            file.file(),
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )?;
        let guard = Self { file };
        guard.file.verify_identity()?;
        Ok(guard)
    }
}

impl Drop for StateLock {
    fn drop(&mut self) {
        // Unlock the description we acquired even if another process briefly
        // inherited a descriptor before exec. Keep the persistent lock inode.
        let _ = rustix::fs::flock(self.file.file(), rustix::fs::FlockOperation::Unlock);
    }
}

fn coordinator_lock(data_dir: &Path) -> anyhow::Result<StateLock> {
    let directory = PrivateStateDirectory::open_for_administration(data_dir)?;
    StateLock::acquire(directory.create_file(snapshot::COORDINATOR)?)
}

fn apply_inner(
    journal: &mut UpgradeJournal,
    control: &mut impl ServiceControl,
) -> anyhow::Result<()> {
    transition(journal, UpgradePhase::MaintenanceIntent)?;
    gate(journal)?;
    ensure!(
        all_stopped(&journal.plan, control)?,
        "service remains active"
    );
    let state = PrivateStateDirectory::open_for_administration(&journal.plan.data_dir)?;
    let maintenance = state.try_maintenance_lock()?;
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
    if journal.native_backup.is_some() {
        backup_bytes = backup_bytes
            .checked_add(native_release::backup_original(journal)?)
            .context("complete backup size overflow")?;
        ensure!(
            backup_bytes <= journal.plan.max_backup_bytes,
            "complete backup exceeds declared byte limit"
        );
    }
    for (index, resource) in journal.plan.resources.iter().enumerate() {
        let primary = resource.path == journal.plan.data_dir;
        let entries = snapshot::inventory(
            &resource.path,
            resource.kind == ResourceType::Directory,
            journal.plan.max_backup_bytes,
            primary,
        )?;
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
            entries
                == snapshot::inventory(
                    &resource.path,
                    resource.kind == ResourceType::Directory,
                    journal.plan.max_backup_bytes,
                    primary
                )?,
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
    if before_validation != inventory_current(journal)? {
        return Err(StructureFailure::Validation.into());
    }
    ensure!(
        all_stopped(&journal.plan, control)?,
        "a state writer restarted during validation"
    );
    transition(journal, UpgradePhase::Validated)?;
    state.verify_identity()?;
    transition(journal, UpgradePhase::SwitchIntent)?;
    if journal.native_backup.is_some() {
        native_release::install_target(journal)?;
    } else {
        install(
            &staged_target,
            &journal.plan.installed_binary,
            &journal.release.binary_sha256,
            journal.original_binary_mode,
        )?;
    }
    transition(journal, UpgradePhase::Switched)?;
    // Persist possible writes before removing the gate and releasing the lock.
    journal.new_program_may_have_written = true;
    transition(journal, UpgradePhase::StartIntent)?;
    clear_gate(journal)?;
    maintenance.release()?;
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
    Ok(())
}

fn install(source: &Path, target: &Path, digest: &str, mode: u32) -> anyhow::Result<()> {
    ensure!(
        snapshot::digest_file(source)? == digest,
        "release changed before switch"
    );
    let stage = target.with_file_name(format!(".upgrade-binary-{}", Uuid::new_v4()));
    snapshot::copy_regular(source, &stage, mode)?;
    ensure!(
        snapshot::digest_file(&stage)? == digest,
        "staged release checksum differs"
    );
    fs::rename(&stage, target)?;
    snapshot::sync_parent(target)?;
    ensure!(
        snapshot::digest_file(target)? == digest,
        "installed release checksum differs"
    );
    Ok(())
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

fn gate(journal: &UpgradeJournal) -> anyhow::Result<()> {
    let path = journal.plan.data_dir.join(PENDING);
    if let Ok(bytes) = snapshot::read_bounded(&path, MAX_JSON) {
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        ensure!(
            value.get("operation_id") == Some(&serde_json::to_value(journal.operation_id)?),
            "another upgrade owns the pending gate"
        );
    } else {
        ensure!(
            fs::symlink_metadata(&path)
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
            "pending gate cannot be safely read"
        );
    }
    let directory =
        xcsc::fs_safety::PrivateDirectory::open_for_administration(&journal.plan.data_dir)?;
    xcsc::fs_safety::AtomicFile::replace(
        &directory,
        &xcsc::fs_safety::RelativePath::new(PENDING)?,
        &serde_json::to_vec(&serde_json::json!({
            "journal_version": 1, "operation_id": journal.operation_id,
            "work_directory": journal.plan.work_directory, "phase": journal.phase,
            "data_dir": journal.plan.data_dir,
            "data_directory_device": fs::symlink_metadata(&journal.plan.data_dir)?.dev(),
            "data_directory_inode": fs::symlink_metadata(&journal.plan.data_dir)?.ino(),
            "target_binary_sha256": journal.release.binary_sha256,
        }))?,
    )?;
    Ok(())
}

fn clear_gate(journal: &UpgradeJournal) -> anyhow::Result<()> {
    let path = journal.plan.data_dir.join(PENDING);
    let bytes = snapshot::read_bounded(&path, MAX_JSON)?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    ensure!(
        value.get("operation_id") == Some(&serde_json::to_value(journal.operation_id)?),
        "pending gate ownership differs"
    );
    xcsc::fs_safety::PrivateDirectory::open_for_administration(&journal.plan.data_dir)?
        .remove_file(&xcsc::fs_safety::EntryName::new(PENDING)?)?;
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
        let path = journal
            .plan
            .work_directory
            .join(format!("resource-{index}"));
        ensure!(
            snapshot::inventory(
                &path,
                backup.resource.kind == ResourceType::Directory,
                journal.plan.max_backup_bytes,
                false
            )? == backup.entries,
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
            snapshot::inventory(
                &resource.path,
                resource.kind == ResourceType::Directory,
                journal.plan.max_backup_bytes,
                resource.path == journal.plan.data_dir,
            )
        })
        .collect()
}

fn verify_unchanged(journal: &UpgradeJournal) -> anyhow::Result<()> {
    for backup in &journal.backups {
        ensure!(
            snapshot::ownership(&backup.resource.path, &backup.entries)? == backup.ownership,
            "state ownership changed"
        );
        ensure!(
            snapshot::inventory(
                &backup.resource.path,
                backup.resource.kind == ResourceType::Directory,
                journal.plan.max_backup_bytes,
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
        execution::verify(&journal)?;
        native_release::validate_artifact(&journal.plan, &journal.release)?;
        ensure!(
            journal.native_backup.is_some() == journal.release.artifact.is_some(),
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
            "journal additional writer mapping differs from signed release"
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
    let installed_program = match installed_binary_sha256.as_deref() {
        Some(value) if value == journal.original_binary_sha256 => "original",
        Some(value) if value == journal.release.binary_sha256 => "target",
        Some(_) => "unknown",
        None => "unreadable",
    };
    let installed_program = if journal.native_backup.is_some() {
        native_release::program_status(&journal).unwrap_or("unreadable")
    } else {
        installed_program
    };
    let persistent_state_verification = if !journal.backup_complete {
        "no-complete-backup"
    } else if verify_unchanged(&journal).is_ok() {
        "matches-backup"
    } else {
        "changed-or-unreadable"
    };
    let maintenance_pending = fs::symlink_metadata(journal.plan.data_dir.join(PENDING)).is_ok();
    Ok(UpgradeInspection {
        journal,
        installed_program,
        installed_binary_sha256,
        maintenance_pending,
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
    let _release_upgrade = native_release::coordinate(&journal.plan).map_err(|_| {
        failure(
            "MAINTENANCE_BUSY",
            "The release directory is in use by another maintenance process, or the directory is unsafe.",
            Some(work_directory),
        )
    })?;
    if journal.phase == UpgradePhase::RolledBack {
        return Ok(journal);
    }
    let _instance_upgrade = coordinator_lock(&journal.plan.data_dir).map_err(|_| {
        failure(
            "MAINTENANCE_BUSY",
            "Another maintenance process is operating on this data directory.",
            Some(work_directory),
        )
    })?;
    if (journal.new_program_may_have_written || journal.recovered_program_may_have_written)
        && !allow_data_loss
    {
        return Err(failure(
            "RECOVERY_AUTHORIZATION_REQUIRED",
            "Runtime ownership has been transferred to the target program, which may have received new business writes. Restoring the old backup discards those writes; use --allow-data-loss only with explicit authorization.",
            Some(work_directory),
        ));
    }
    if journal.phase != UpgradePhase::Prechecked {
        require_stopped(&journal.plan, control)?;
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
        // Prechecked has no gate or resource changes; close its record without
        // changing a service that the operator may have subsequently started.
        if journal.phase == UpgradePhase::Prechecked {
            ensure!(
                snapshot::digest_file(&native_release::installed_binary(&journal.plan)?)?
                    == journal.original_binary_sha256,
                "installed binary differs from the precheck"
            );
            return transition(&mut journal, UpgradePhase::RolledBack);
        }
        transition(&mut journal, UpgradePhase::RecoveryMaintenanceIntent)?;
        gate(&journal)?;
        ensure!(
            all_stopped(&journal.plan, control)?,
            "service remains active during recovery"
        );
        let state = PrivateStateDirectory::open_for_administration(&journal.plan.data_dir)?;
        let maintenance = state.try_maintenance_lock()?;
        ensure!(
            all_stopped(&journal.plan, control)?,
            "service restarted during recovery maintenance acquisition"
        );
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
            if journal.native_backup.is_some() && native_release::original_needs_repair(&journal)? {
                journal
                    .native_backup
                    .as_mut()
                    .context("native repair mapping missing")?
                    .source_recovery_started = true;
                save(&journal)?;
            }
            for (index, backup) in journal.backups.iter().enumerate() {
                snapshot::restore(
                    &work_directory.join(format!("resource-{index}")),
                    &backup.resource.path,
                    &backup.entries,
                    backup.resource.path == journal.plan.data_dir,
                    // The verified snapshot must fit the backup budget, but
                    // current data may have grown since runtime handoff. Its
                    // authorized replacement must not reuse that old budget.
                    u64::MAX,
                    &backup.ownership,
                )?;
                snapshot::restore_ownership(
                    &backup.resource.path,
                    &backup.entries,
                    &backup.ownership,
                )?;
            }
            if journal.native_backup.is_some() {
                native_release::restore_original(&journal)?;
            } else {
                install(
                    &work_directory.join("original-binary"),
                    &journal.plan.installed_binary,
                    &journal.original_binary_sha256,
                    journal.original_binary_mode,
                )?;
            }
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
        clear_gate(&journal)?;
        maintenance.release()?;
        control.start(&journal.plan)?;
        wait_ready(&journal, control, &journal.original_binary_sha256)?;
        transition(&mut journal, UpgradePhase::RolledBack)
    })();
    result.map_err(|_error| {
        failure(
            "RECOVERY_EXECUTION_FAILED",
            format!("Recovery interrupted during {:?}. The original journal and backups were preserved.", journal.phase),
            Some(work_directory),
        )
    })?;
    Ok(journal)
}
