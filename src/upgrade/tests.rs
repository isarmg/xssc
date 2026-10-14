use super::*;
use std::os::unix::fs::PermissionsExt;

#[test]
fn restore_read_only_directories_preserves_contents_modes_and_ownership() {
    // A root process would hide the permission regression. Exercise the same
    // test as an ordinary user even when the suite is launched by root.
    if rustix::process::geteuid().as_raw() == 0 {
        use std::os::unix::process::CommandExt;
        let temporary = tempfile::tempdir().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let executable = temporary.path().join("nonroot-restore-test");
        fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::File::open(&executable)
            .unwrap()
            .sync_all()
            .unwrap();
        let mut command = std::process::Command::new(&executable);
        command.args([
                "--exact",
                "upgrade::tests::restore_read_only_directories_preserves_contents_modes_and_ownership",
                "--nocapture",
            ])
            .uid(65534)
            .gid(65534)
            ;
        let mut retries = 0;
        let output = loop {
            match command.output() {
                Ok(output) => break output,
                Err(error)
                    if error.kind() == std::io::ErrorKind::ExecutableFileBusy && retries < 10 =>
                {
                    retries += 1;
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(error) => panic!("spawn nonroot restore fixture: {error}"),
            }
        };
        assert!(
            output.status.success(),
            "non-root restore failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    for mode in [0o500, 0o555] {
        let temporary = tempfile::tempdir().unwrap();
        let original = temporary.path().join("original");
        let backup = temporary.path().join("backup");
        let target = temporary.path().join("target");
        for root in [&original, &target] {
            snapshot::private_directory(root).unwrap();
            snapshot::private_directory(&root.join("nested")).unwrap();
            snapshot::private_directory(&root.join("nested/deeper")).unwrap();
            fs::write(root.join("nested/object"), b"original object").unwrap();
            fs::write(root.join("nested/deeper/object"), b"nested object").unwrap();
            for relative in ["nested/deeper", "nested"] {
                fs::set_permissions(root.join(relative), fs::Permissions::from_mode(mode)).unwrap();
            }
        }
        fs::write(original.join("operator-file"), b"original operator file").unwrap();
        let entries = snapshot::inventory(&original, true, 4096, true).unwrap();
        let owners = snapshot::ownership(&original, &entries).unwrap();
        snapshot::snapshot(&original, &backup, &entries).unwrap();
        let gate = target.join("operator-file");
        fs::write(&gate, b"pending gate").unwrap();
        let result = (|| -> anyhow::Result<()> {
            // Include an extra entry to verify replacement and repeat recovery
            // from an already restored read-only directory tree.
            for _ in 0..2 {
                fs::write(target.join("obsolete"), b"remove during restore")?;
                snapshot::restore(&backup, &target, &entries, true, 4096, &owners)?;
                assert_eq!(snapshot::inventory(&target, true, 4096, true)?, entries);
                assert_eq!(snapshot::ownership(&target, &entries)?, owners);
                assert_eq!(fs::read(target.join("nested/object"))?, b"original object");
                assert_eq!(
                    fs::read(target.join("nested/deeper/object"))?,
                    b"nested object"
                );
                assert_eq!(fs::read(&gate)?, b"original operator file");
                assert!(!target.join("obsolete").exists());
            }
            Ok(())
        })();
        // Allow TempDir to remove the fixture even if restoration failed.
        for root in [&original, &backup, &target] {
            for relative in ["", "nested", "nested/deeper"] {
                let _ = fs::set_permissions(root.join(relative), fs::Permissions::from_mode(0o700));
            }
        }
        result.unwrap();
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    plan: UpgradePlan,
    release: UpgradeRelease,
    root: PathBuf,
    target: PathBuf,
    services: Vec<native_release::PackageService>,
}

impl Fixture {
    fn new() -> Self {
        Self::product("xocs")
    }
    fn product(product: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let base = directory.path();
        let root = base.join("installation");
        let target = base.join("download");
        for directory in [&root, &target] {
            fs::create_dir_all(directory.join("bin")).unwrap();
            fs::create_dir_all(directory.join("libexec")).unwrap();
            fs::create_dir_all(directory.join("share/systemd")).unwrap();
            for path in [
                directory.clone(),
                directory.join("bin"),
                directory.join("libexec"),
                directory.join("share"),
                directory.join("share/systemd"),
            ] {
                fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
            }
            snapshot::copy_regular(
                Path::new("/usr/bin/true"),
                &directory.join("libexec/setup"),
                0o755,
            )
            .unwrap();
            fs::write(
                directory
                    .join("share/systemd")
                    .join(format!("{product}.service")),
                b"checksummed systemd fixture",
            )
            .unwrap();
        }
        snapshot::copy_regular(
            Path::new("/usr/bin/false"),
            &root.join("bin").join(product),
            0o755,
        )
        .unwrap();
        snapshot::copy_regular(
            Path::new("/usr/bin/true"),
            &target.join("bin").join(product),
            0o755,
        )
        .unwrap();
        fs::write(
            root.join("share/obsolete"),
            b"obsolete checksummed resource",
        )
        .unwrap();
        fs::write(
            target.join("share/new-resource"),
            b"new checksummed resource",
        )
        .unwrap();
        for path in [
            root.join("state"),
            root.join("logs"),
            root.join("config"),
            root.join("maintenance"),
            root.join("maintenance/upgrades"),
        ] {
            snapshot::private_directory(&path).unwrap();
        }
        let data = root.join("state");
        let config = root.join("config/config.json");
        fs::write(&config, b"{\"current\":true}\n").unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(data.join(".state-instance.lock"), b"").unwrap();
        fs::set_permissions(
            data.join(".state-instance.lock"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fs::write(data.join("business.txt"), b"business-before-upgrade").unwrap();
        snapshot::private_directory(&data.join("nested")).unwrap();
        fs::write(data.join("nested/object"), b"object-before-upgrade").unwrap();
        let schema = SchemaIdentity::new(product, "database-current", 1, "a".repeat(64)).unwrap();
        let source = ReleaseIdentity {
            product: product.into(),
            version: "1.0.0".into(),
            source_revision: "d".repeat(40),
            target: crate::FORMAL_RELEASE_TARGET.into(),
            state_contract_sha256: "e".repeat(64),
        };
        let identity = ReleaseIdentity {
            version: "2.0.0".into(),
            source_revision: "b".repeat(40),
            ..source.clone()
        };
        let services = vec![native_release::PackageService {
            name: format!("{product}.service"),
            path: format!("share/systemd/{product}.service").into(),
            role: "server".into(),
        }];
        let resources = vec![
            PersistentResource {
                name: "config".into(),
                path: config.clone(),
                kind: ResourceType::File,
            },
            PersistentResource {
                name: "data".into(),
                path: data.clone(),
                kind: ResourceType::Directory,
            },
            PersistentResource {
                name: "logs".into(),
                path: root.join("logs"),
                kind: ResourceType::Directory,
            },
        ];
        let plan = UpgradePlan {
            plan_version: 1,
            service: format!("{product}.service"),
            additional_services: Vec::new(),
            installed_binary: root.join("bin").join(product),
            target_binary: target.join("bin").join(product),
            release_manifest: target.join("share/package.json"),
            release_checksum: target.join("share/package.sha256"),
            config,
            data_dir: data,
            resources: resources.clone(),
            work_directory: root
                .join("maintenance/upgrades")
                .join(Uuid::new_v4().to_string()),
            readiness_address: "127.0.0.1:12345".parse().unwrap(),
            timeout_seconds: 1,
            max_backup_bytes: 10_000_000,
            native_release: Some(NativeReleasePlan {
                root: root.clone(),
                source_manifest: root.join("share/package.json"),
            }),
        };
        let release = UpgradeRelease {
            manifest_version: 1,
            source_identity: source.clone(),
            identity,
            binary_sha256: snapshot::digest_file(&plan.target_binary).unwrap(),
            source_schema: schema.clone(),
            target_schema: schema.clone(),
            artifact: None,
            resources: resources
                .iter()
                .map(|r| ReleaseResource {
                    name: r.name.clone(),
                    kind: r.kind,
                })
                .collect(),
            additional_service_roles: Vec::new(),
        };
        let fixture = Self {
            _directory: directory,
            plan,
            release,
            root,
            target,
            services,
        };
        fixture.package(&fixture.root, &source, &schema);
        fixture.finalize();
        fixture
    }
    fn package(&self, root: &Path, identity: &ReleaseIdentity, schema: &SchemaIdentity) {
        let mut files = Vec::new();
        fn scan(root: &Path, path: &Path, files: &mut Vec<native_release::PayloadFile>) {
            let mut entries = fs::read_dir(path)
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            entries.sort_by_key(|e| e.file_name());
            for entry in entries {
                let path = entry.path();
                let relative = path.strip_prefix(root).unwrap();
                if matches!(
                    relative.to_str().unwrap(),
                    "share/package.json" | "share/package.sha256"
                ) {
                    continue;
                }
                if entry.file_type().unwrap().is_dir() {
                    scan(root, &path, files);
                } else {
                    let mode =
                        if relative.starts_with("bin") || relative == Path::new("libexec/setup") {
                            0o755
                        } else {
                            0o644
                        };
                    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
                    files.push(native_release::PayloadFile {
                        path: relative.to_path_buf(),
                        mode: format!("{mode:04o}"),
                        size: fs::metadata(&path).unwrap().len(),
                        sha256: snapshot::digest_file(&path).unwrap(),
                    });
                }
            }
        }
        for name in ["bin", "libexec", "share"] {
            scan(root, &root.join(name), &mut files);
        }
        files.sort_by_key(|f| f.path.clone());
        let package = native_release::PackageManifest {
            manifest_version: 1,
            identity: identity.clone(),
            schema_identity: schema.clone(),
            server: format!("bin/{}", identity.product).into(),
            setup: "libexec/setup".into(),
            services: self.services.clone(),
            files,
        };
        let manifest = root.join("share/package.json");
        fs::write(&manifest, serde_json::to_vec(&package).unwrap()).unwrap();
        fs::set_permissions(&manifest, fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(
            root.join("share/package.sha256"),
            format!("{}\n", snapshot::digest_file(&manifest).unwrap()),
        )
        .unwrap();
        fs::set_permissions(
            root.join("share/package.sha256"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
    }
    fn finalize(&self) {
        self.package(
            &self.target,
            &self.release.identity,
            &self.release.target_schema,
        );
    }
    fn delegate_state_when_administrator(&self) {
        if rustix::process::geteuid().as_raw() != 0 {
            return;
        }
        fs::set_permissions(self._directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let entries = snapshot::inventory(&self.plan.data_dir, true, 1024, true).unwrap();
        for entry in entries {
            let path = if entry.path.as_os_str().is_empty() {
                self.plan.data_dir.clone()
            } else {
                self.plan.data_dir.join(entry.path)
            };
            let file = fs::File::open(path).unwrap();
            rustix::fs::fchown(
                &file,
                Some(rustix::process::Uid::from_raw(65534)),
                Some(rustix::process::Gid::from_raw(65534)),
            )
            .unwrap();
        }
    }
    fn control(&self) -> MockControl {
        MockControl {
            schema: self.release.source_schema.clone(),
            active: false,
            active_services: BTreeSet::new(),
            fail_start: false,
            fail_stop: false,
            fail_target_validation: false,
            mutate_validator: false,
            validate_calls: 0,
            uncovered: None,
            shared_paths: Vec::new(),
            fail_precheck_identity: false,
        }
    }
}

struct MockControl {
    schema: SchemaIdentity,
    active: bool,
    active_services: BTreeSet<String>,
    fail_start: bool,
    fail_stop: bool,
    fail_target_validation: bool,
    mutate_validator: bool,
    validate_calls: usize,
    uncovered: Option<PathBuf>,
    shared_paths: Vec<PathBuf>,
    fail_precheck_identity: bool,
}
impl ServiceControl for MockControl {
    fn verify_release_identity(
        &mut self,
        binary: &Path,
        plan: &UpgradePlan,
        _identity: &ReleaseIdentity,
    ) -> anyhow::Result<()> {
        ensure!(
            !self.fail_precheck_identity || binary == plan.installed_binary,
            "injected staged identity failure"
        );
        Ok(())
    }
    fn stop(&mut self, journal: &mut UpgradeJournal) -> anyhow::Result<()> {
        let plan = &journal.plan;
        ensure!(!self.fail_stop, "injected state-writer shutdown failure");
        self.active = false;
        self.active_services.remove(&plan.service);
        for service in &plan.additional_services {
            self.active_services.remove(&service.service);
        }
        Ok(())
    }
    fn is_stopped(&mut self, plan: &UpgradePlan) -> anyhow::Result<bool> {
        Ok(!self.active && !self.active_services.contains(&plan.service))
    }
    fn start(&mut self, _plan: &UpgradePlan) -> anyhow::Result<()> {
        ensure!(!self.fail_start, "injected start failure");
        self.active = true;
        Ok(())
    }
    fn configuration(
        &mut self,
        _binary: &Path,
        plan: &UpgradePlan,
        _artifact: Option<&ReleaseArtifact>,
    ) -> anyhow::Result<serde_json::Value> {
        let mut paths = vec![
            plan.config.clone(),
            plan.data_dir.clone(),
            installation_root(plan)?.join("logs"),
        ];
        if let Some(path) = &self.uncovered {
            paths.push(path.clone());
        }
        paths.extend(self.shared_paths.clone());
        Ok(
            serde_json::json!({"root":installation_root(plan)?,"product":service_product(plan)?,"data_dir":plan.data_dir,"state_paths":paths,"shared_paths":self.shared_paths,"business_paths":self.shared_paths,"runtime_locks":[{"path":plan.data_dir.join(".state-instance.lock"),"kind":"file"}]}),
        )
    }
    fn validate(
        &mut self,
        _binary: &Path,
        plan: &UpgradePlan,
        _artifact: Option<&ReleaseArtifact>,
    ) -> anyhow::Result<ValidatedState> {
        self.validate_calls += 1;
        if self.validate_calls == 2 {
            ensure!(
                !self.fail_target_validation,
                "injected target validation failure"
            );
            if self.mutate_validator {
                fs::write(
                    plan.data_dir.join("business.txt"),
                    b"unexpected-validator-write",
                )?;
            }
        }
        let mut state_paths = vec![
            plan.config.clone(),
            plan.data_dir.clone(),
            installation_root(plan)?.join("logs"),
        ];
        state_paths.extend(self.shared_paths.clone());
        Ok(ValidatedState {
            schema_identity: self.schema.clone(),
            state_paths,
        })
    }
    fn ready(&mut self, _plan: &UpgradePlan, _hash: &str, _identity: &str) -> anyhow::Result<bool> {
        Ok(self.active)
    }
}

#[test]
fn payload_snapshot_records_only_a_new_root_before_copying_contents() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    snapshot::private_directory(&source).unwrap();
    fs::write(source.join("program"), b"original immutable bytes").unwrap();
    let entries = snapshot::inventory(&source, true, 1024, false).unwrap();
    let target = temporary.path().join("target");
    let mut recorded = None;
    assert!(
        snapshot::snapshot_recorded(&source, &target, &entries, |path, metadata| {
            assert_eq!(path, target);
            assert_eq!(metadata.mode() & 0o777, 0o700);
            assert!(!path.join("program").exists());
            recorded = Some((metadata.dev(), metadata.ino()));
            anyhow::bail!("simulated durable journal failure");
        })
        .is_err()
    );
    let metadata = fs::symlink_metadata(&target).unwrap();
    assert_eq!(recorded, Some((metadata.dev(), metadata.ino())));
    assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
    fs::write(target.join("administrator-note"), b"existing content").unwrap();
    let mut called = false;
    assert!(
        snapshot::snapshot_recorded(&source, &target, &entries, |_, _| {
            called = true;
            Ok(())
        })
        .is_err()
    );
    assert!(!called);
    assert_eq!(
        fs::read(target.join("administrator-note")).unwrap(),
        b"existing content"
    );
}

#[test]
fn precheck_cleanup_preserves_an_unrecorded_payload_directory() {
    let fixture = Fixture::new();
    let mut control = fixture.control();
    control.fail_precheck_identity = true;
    apply(&fixture.plan, &mut control).unwrap_err();
    let mut journal = inspect(&fixture.plan.work_directory).unwrap();
    journal.phase = UpgradePhase::Prechecked;
    journal.native_backup = None;
    let stage = fixture.plan.work_directory.join("target-payload");
    snapshot::private_directory(&stage).unwrap();
    fs::write(stage.join("administrator-note"), b"unrecorded content").unwrap();
    execution::cleanup_precheck(&journal).unwrap();
    assert_eq!(
        fs::read(stage.join("administrator-note")).unwrap(),
        b"unrecorded content"
    );
}

#[test]
fn precheck_without_native_backup_recovers_only_its_recorded_payload_root() {
    let fixture = Fixture::new();
    let before = fs::read(fixture.plan.data_dir.join("business.txt")).unwrap();
    let mut control = fixture.control();
    control.fail_precheck_identity = true;
    apply(&fixture.plan, &mut control).unwrap_err();
    let mut journal = inspect(&fixture.plan.work_directory).unwrap();
    journal.phase = UpgradePhase::Prechecked;
    journal.native_backup = None;
    let stage = fixture.plan.work_directory.join("target-payload");
    snapshot::private_directory(&stage).unwrap();
    let parent = fs::symlink_metadata(&fixture.plan.work_directory).unwrap();
    let directory = fs::symlink_metadata(&stage).unwrap();
    journal.payload_stage_seal = Some(execution::StageAuthority {
        root: stage.clone(),
        parent_device: parent.dev(),
        parent_inode: parent.ino(),
        directory_device: directory.dev(),
        directory_inode: directory.ino(),
    });
    save(&journal).unwrap();
    assert!(
        inspect(&fixture.plan.work_directory)
            .unwrap()
            .native_backup
            .is_none()
    );
    control.active = true;
    let recovered = recover(&fixture.plan.work_directory, false, &mut control).unwrap();
    assert_eq!(recovered.phase, UpgradePhase::RolledBack);
    assert!(recovered.payload_stage_seal.is_none());
    assert!(!stage.exists());
    assert!(control.active);
    assert_eq!(
        fs::read(fixture.plan.data_dir.join("business.txt")).unwrap(),
        before
    );
}

#[test]
fn private_or_deleted_payload_precheck_is_recoverable_without_execution() {
    for interruption in ["private-payload", "removed-payload"] {
        let fixture = Fixture::new();
        let before = fs::read(fixture.plan.data_dir.join("business.txt")).unwrap();
        let mut control = fixture.control();
        control.fail_precheck_identity = true;
        apply(&fixture.plan, &mut control).unwrap_err();
        let mut journal = inspect(&fixture.plan.work_directory).unwrap();
        journal.phase = UpgradePhase::Prechecked;
        journal.native_backup = None;
        let stage = journal.plan.work_directory.join("target-payload");
        if interruption == "private-payload" {
            snapshot::private_directory(&stage).unwrap();
            let parent = fs::symlink_metadata(&journal.plan.work_directory).unwrap();
            let created = fs::symlink_metadata(&stage).unwrap();
            execution::record_payload_stage(&mut journal, &stage, &created).unwrap();
            assert_eq!(
                journal.payload_stage_seal.as_ref().unwrap().parent_inode,
                parent.ino()
            );
        } else {
            native_release::seal(&mut journal).unwrap();
            journal.native_backup = None;
            save(&journal).unwrap();
            fs::remove_dir_all(&stage).unwrap();
        }
        assert!(
            inspect(&fixture.plan.work_directory).is_ok(),
            "{interruption}"
        );
        control.active = true;
        let recovered = recover(&fixture.plan.work_directory, false, &mut control).unwrap();
        assert_eq!(recovered.phase, UpgradePhase::RolledBack);
        assert!(recovered.payload_stage_seal.is_none());
        assert!(recovered.work_directory_seal.is_some());
        assert!(!stage.exists());
        assert!(control.active);
        assert_eq!(
            fs::read(fixture.plan.data_dir.join("business.txt")).unwrap(),
            before
        );
    }
}

#[test]
fn copied_journal_cannot_change_operation_and_noncanonical_ids_are_rejected() {
    let fixture = Fixture::new();
    let mut control = fixture.control();
    control.fail_precheck_identity = true;
    apply(&fixture.plan, &mut control).unwrap_err();
    let journal = inspect(&fixture.plan.work_directory).unwrap();
    let work = fixture
        .root
        .join("maintenance/upgrades")
        .join(Uuid::new_v4().to_string());
    snapshot::private_directory(&work).unwrap();
    let mut copied = journal.clone();
    copied.plan.work_directory = work.clone();
    save(&copied).unwrap();
    assert_eq!(inspect(&work).unwrap_err().code, "RECOVERY_STATE_INVALID");
    let original = fs::read(fixture.plan.work_directory.join(JOURNAL)).unwrap();
    for operation in [
        journal.operation_id.simple().to_string(),
        journal.operation_id.urn().to_string(),
    ] {
        let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
        value["operation_id"] = serde_json::Value::String(operation);
        fs::write(
            fixture.plan.work_directory.join(JOURNAL),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
        assert_eq!(
            inspect(&fixture.plan.work_directory).unwrap_err().code,
            "RECOVERY_STATE_INVALID"
        );
    }
    fs::write(fixture.plan.work_directory.join(JOURNAL), original).unwrap();
    assert!(inspect(&fixture.plan.work_directory).is_ok());
}

#[test]
fn failed_precheck_removes_only_its_owned_stage_and_next_upgrade_succeeds() {
    let mut fixture = Fixture::new();
    fixture.delegate_state_when_administrator();
    let before = fs::read(fixture.plan.data_dir.join("business.txt")).unwrap();
    let unrelated = fixture.root.join("maintenance/administrator-note");
    fs::write(&unrelated, b"unrelated administrator content").unwrap();
    let _operation = Uuid::parse_str(
        fixture
            .plan
            .work_directory
            .file_name()
            .unwrap()
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let mut control = fixture.control();
    control.fail_precheck_identity = true;
    assert_eq!(
        apply(&fixture.plan, &mut control).unwrap_err().code,
        "UPGRADE_PRECONDITION_FAILED"
    );
    assert!(!fixture.plan.work_directory.join("target-payload").exists());
    assert_eq!(
        fs::read(&unrelated).unwrap(),
        b"unrelated administrator content"
    );
    assert_eq!(
        fs::read(fixture.plan.data_dir.join("business.txt")).unwrap(),
        before
    );
    let completed = inspect(&fixture.plan.work_directory).unwrap();
    assert_eq!(completed.phase, UpgradePhase::RolledBack);
    assert!(completed.work_directory_seal.is_some());
    assert!(completed.payload_stage_seal.is_none());
    fs::remove_file(unrelated).unwrap();
    fixture.plan.work_directory = fixture
        .root
        .join("maintenance/upgrades")
        .join(Uuid::new_v4().to_string());
    control.fail_precheck_identity = false;
    assert_eq!(
        apply(&fixture.plan, &mut control).unwrap().phase,
        UpgradePhase::Ready
    );
}

#[test]
fn two_checksum_upgrades_preserve_runtime_writes_and_distinct_bound_work_directories() {
    let mut fixture = Fixture::new();
    fixture.delegate_state_when_administrator();
    let mut first_control = fixture.control();
    let first = apply(&fixture.plan, &mut first_control).unwrap();
    assert_eq!(first.phase, UpgradePhase::Ready);
    if let Some(seal) = &first.work_directory_seal {
        assert!(seal.root.join("target-payload/libexec/setup").is_file());
        execution::verify(&first).unwrap();
    }
    fs::write(
        fixture.plan.data_dir.join("business.txt"),
        b"runtime-write-between-upgrades",
    )
    .unwrap();
    fixture.plan.work_directory = fixture
        .root
        .join("maintenance/upgrades")
        .join(Uuid::new_v4().to_string());
    fixture.release.source_identity = first.release.identity.clone();
    fixture.release.identity.version = "3.0.0".into();
    fixture.release.identity.source_revision = "c".repeat(40);
    fs::write(
        fixture.target.join("share/new-resource"),
        b"third release resource",
    )
    .unwrap();
    fixture.finalize();
    let mut second_control = fixture.control();
    let second = apply(&fixture.plan, &mut second_control).unwrap();
    assert_eq!(second.phase, UpgradePhase::Ready);
    assert_eq!(second.release.source_identity, first.release.identity);
    assert_eq!(
        fs::read(fixture.plan.data_dir.join("business.txt")).unwrap(),
        b"runtime-write-between-upgrades"
    );
    assert_eq!(
        fs::read(fixture.root.join("share/new-resource")).unwrap(),
        b"third release resource"
    );
    execution::verify(&first).unwrap();
    execution::verify(&second).unwrap();
    if rustix::process::geteuid().as_raw() == 0 {
        assert!(first.work_directory_seal.is_some());
        assert!(second.work_directory_seal.is_some());
        assert_ne!(
            first.work_directory_seal.unwrap().root,
            second.work_directory_seal.unwrap().root
        );
    }
}

#[test]
fn checksum_fixed_root_upgrade_preserves_state_and_removes_obsolete_payload() {
    let fixture = Fixture::new();
    let before = fs::read(&fixture.plan.config).unwrap();
    let mut control = fixture.control();
    let result = apply(&fixture.plan, &mut control).unwrap();
    assert_eq!(result.phase, UpgradePhase::Ready);
    assert!(result.backup_complete && result.new_program_may_have_written);
    assert_eq!(
        snapshot::digest_file(&fixture.plan.installed_binary).unwrap(),
        fixture.release.binary_sha256
    );
    assert_eq!(
        fs::read(fixture.plan.data_dir.join("business.txt")).unwrap(),
        b"business-before-upgrade"
    );
    assert_eq!(fs::read(&fixture.plan.config).unwrap(), before);
    assert!(!fixture.root.join("share/obsolete").exists());
    assert_eq!(
        fs::read(fixture.root.join("share/new-resource")).unwrap(),
        b"new checksummed resource"
    );
    assert!(!fixture.root.join("current").exists());
    assert!(!fixture.root.join("releases").exists());
    assert_eq!(
        inspect(&fixture.plan.work_directory).unwrap().phase,
        UpgradePhase::Ready
    );
}

#[test]
fn untrusted_target_or_source_is_rejected_before_maintenance() {
    for source in [false, true] {
        let fixture = Fixture::new();
        let checksum = if source {
            fixture.root.join("share/package.sha256")
        } else {
            fixture.plan.release_checksum.clone()
        };
        fs::write(checksum, [0u8; 64]).unwrap();
        let mut control = fixture.control();
        assert_eq!(
            apply(&fixture.plan, &mut control).unwrap_err().code,
            "ARTIFACT_UNTRUSTED"
        );
        assert!(!fixture.plan.work_directory.exists());
        assert!(!control.active);
    }
}

#[test]
fn complete_payload_bytes_modes_and_platform_are_checked() {
    for mutation in ["bytes", "mode", "platform", "extra"] {
        let mut fixture = Fixture::new();
        match mutation {
            "bytes" => fs::write(fixture.target.join("share/new-resource"), b"tampered").unwrap(),
            "mode" => fs::set_permissions(
                fixture.target.join("libexec/setup"),
                fs::Permissions::from_mode(0o777),
            )
            .unwrap(),
            "platform" => {
                fixture.release.identity.target = "aarch64-unknown-linux-gnu".into();
                fixture.finalize();
            }
            _ => fs::write(
                fixture.target.join("share/undeclared"),
                b"undeclared resource",
            )
            .unwrap(),
        }
        assert!(apply(&fixture.plan, &mut fixture.control()).is_err());
    }
}

#[test]
fn legacy_manifest_and_selector_plan_are_not_accepted() {
    let fixture = Fixture::new();
    fs::write(
        &fixture.plan.release_manifest,
        serde_json::to_vec(&fixture.release).unwrap(),
    )
    .unwrap();
    fs::write(
        &fixture.plan.release_checksum,
        format!(
            "{}\n",
            snapshot::digest_file(&fixture.plan.release_manifest).unwrap()
        ),
    )
    .unwrap();
    assert!(verify_release(&fixture.plan).is_err());
    assert!(serde_json::from_value::<NativeReleasePlan>(serde_json::json!({"current_link":"/opt/project/current","source_root":"/opt/project/releases/1","install_root":"/opt/project/releases/2"})).is_err());
}

#[test]
fn validation_failure_restores_complete_payload_and_persistent_group() {
    let fixture = Fixture::new();
    let original = snapshot::digest_file(&fixture.plan.installed_binary).unwrap();
    let mut control = fixture.control();
    control.fail_target_validation = true;
    apply(&fixture.plan, &mut control).unwrap_err();
    assert!(
        inspect(&fixture.plan.work_directory)
            .unwrap()
            .backup_complete
    );
    let result = recover(&fixture.plan.work_directory, false, &mut control).unwrap();
    assert_eq!(result.phase, UpgradePhase::RolledBack);
    assert!(control.active);
    assert_eq!(
        snapshot::digest_file(&fixture.plan.installed_binary).unwrap(),
        original
    );
    assert!(fixture.root.join("share/obsolete").is_file());
    assert!(!fixture.root.join("share/new-resource").exists());
}

#[test]
fn read_only_validator_side_effects_are_detected_and_restored() {
    let fixture = Fixture::new();
    let mut control = fixture.control();
    control.mutate_validator = true;
    assert_eq!(
        apply(&fixture.plan, &mut control).unwrap_err().code,
        "UPGRADE_STATE_VALIDATION_FAILED"
    );
    assert_eq!(
        fs::read(fixture.plan.data_dir.join("business.txt")).unwrap(),
        b"unexpected-validator-write"
    );
    recover(&fixture.plan.work_directory, false, &mut control).unwrap();
    assert_eq!(
        fs::read(fixture.plan.data_dir.join("business.txt")).unwrap(),
        b"business-before-upgrade"
    );
}

#[test]
fn startup_failure_protects_new_writes_until_explicit_recovery_authorization() {
    let fixture = Fixture::new();
    let mut control = fixture.control();
    control.fail_start = true;
    apply(&fixture.plan, &mut control).unwrap_err();
    assert_eq!(
        inspect(&fixture.plan.work_directory).unwrap().phase,
        UpgradePhase::StartIntent
    );
    fs::write(
        fixture.plan.data_dir.join("business.txt"),
        b"new-business-write",
    )
    .unwrap();
    assert_eq!(
        recover(&fixture.plan.work_directory, false, &mut control)
            .unwrap_err()
            .code,
        "RECOVERY_AUTHORIZATION_REQUIRED"
    );
    assert_eq!(
        fs::read(fixture.plan.data_dir.join("business.txt")).unwrap(),
        b"new-business-write"
    );
    control.fail_start = false;
    control.active = false;
    recover(&fixture.plan.work_directory, true, &mut control).unwrap();
    assert_eq!(
        fs::read(fixture.plan.data_dir.join("business.txt")).unwrap(),
        b"business-before-upgrade"
    );
}

#[test]
fn recovery_restart_failure_also_preserves_post_start_write_authority() {
    let fixture = Fixture::new();
    let mut control = fixture.control();
    control.fail_target_validation = true;
    apply(&fixture.plan, &mut control).unwrap_err();
    control.fail_start = true;
    recover(&fixture.plan.work_directory, false, &mut control).unwrap_err();
    assert_eq!(
        inspect(&fixture.plan.work_directory).unwrap().phase,
        UpgradePhase::RecoveryStartIntent
    );
    assert_eq!(
        recover(&fixture.plan.work_directory, false, &mut control)
            .unwrap_err()
            .code,
        "RECOVERY_AUTHORIZATION_REQUIRED"
    );
}

#[test]
fn undeclared_or_broadened_resource_is_refused_before_backup() {
    let fixture = Fixture::new();
    let mut control = fixture.control();
    control.uncovered = Some(fixture._directory.path().join("external-media"));
    assert_eq!(
        apply(&fixture.plan, &mut control).unwrap_err().code,
        "UPGRADE_RESOURCE_COVERAGE_FAILED"
    );
    assert!(
        !inspect(&fixture.plan.work_directory)
            .unwrap()
            .backup_complete
    );
    assert!(!fixture.plan.work_directory.join("resource-0").exists());
    let mut plan = fixture.plan.clone();
    plan.resources.push(PersistentResource {
        name: "unrelated".into(),
        path: fixture._directory.path().to_path_buf(),
        kind: ResourceType::Directory,
    });
    assert!(validate_plan(&plan).is_err());
}

#[test]
fn writer_shutdown_failure_and_tool_lock_prevent_snapshot_or_switch() {
    let fixture = Fixture::new();
    let mut control = fixture.control();
    control.active = true;
    control.fail_stop = true;
    assert_eq!(
        apply(&fixture.plan, &mut control).unwrap_err().code,
        "UPGRADE_EXECUTION_FAILED"
    );
    assert!(!fixture.plan.work_directory.join("resource-0").exists());
    assert_eq!(
        inspect(&fixture.plan.work_directory).unwrap().phase,
        UpgradePhase::MaintenanceIntent
    );
    control.active = false;
    control.fail_stop = false;
    if rustix::process::geteuid().as_raw() != 0 {
        return;
    }
    let _operation = native_release::coordinate(&fixture.plan, None).unwrap();
    assert!(apply(&fixture.plan, &mut control).is_err());
    assert!(!fixture.plan.work_directory.join("resource-0").exists());
}

#[test]
fn corrupt_complete_backup_cannot_overwrite_current_state() {
    let fixture = Fixture::new();
    let mut control = fixture.control();
    control.fail_target_validation = true;
    apply(&fixture.plan, &mut control).unwrap_err();
    fs::write(
        fixture.plan.work_directory.join("resource-1/business.txt"),
        b"corrupt",
    )
    .unwrap();
    assert_eq!(
        recover(&fixture.plan.work_directory, false, &mut control)
            .unwrap_err()
            .code,
        "RECOVERY_STATE_INVALID"
    );
    assert_eq!(
        fs::read(fixture.plan.data_dir.join("business.txt")).unwrap(),
        b"business-before-upgrade"
    );
}

#[test]
fn different_current_schema_is_rejected_without_conversion() {
    let mut fixture = Fixture::new();
    fixture.release.target_schema.schema_revision = 2;
    fixture.finalize();
    let mut control = fixture.control();
    assert!(apply(&fixture.plan, &mut control).is_err());
    assert!(!control.active);
    assert_eq!(
        fs::read(fixture.plan.data_dir.join("business.txt")).unwrap(),
        b"business-before-upgrade"
    );
}

#[test]
fn declared_shared_business_root_preserves_mixed_owners_and_group_modes_through_recovery() {
    if rustix::process::geteuid().as_raw() != 0 {
        return;
    }
    let mut fixture = Fixture::product("xczs");
    let shared = fixture._directory.path().join("shared");
    fs::create_dir(&shared).unwrap();
    fs::write(shared.join("document"), b"shared original").unwrap();
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o775)).unwrap();
    fs::set_permissions(shared.join("document"), fs::Permissions::from_mode(0o664)).unwrap();
    for (path, uid, gid) in [
        (&shared, 65534, 65534),
        (&shared.join("document"), 65533, 65533),
    ] {
        let file = fs::File::open(path).unwrap();
        rustix::fs::fchown(
            &file,
            Some(rustix::process::Uid::from_raw(uid)),
            Some(rustix::process::Gid::from_raw(gid)),
        )
        .unwrap();
    }
    set_posix_acl(
        &shared,
        "system.posix_acl_access",
        &posix_acl(7, 7, 5, 7, 5),
    );
    set_posix_acl(
        &shared,
        "system.posix_acl_default",
        &posix_acl(7, 7, 5, 7, 5),
    );
    set_posix_acl(
        &shared.join("document"),
        "system.posix_acl_access",
        &posix_acl(6, 6, 4, 6, 4),
    );
    set_mtime(&shared, 1_580_000_001, 123_456_789);
    set_mtime(&shared.join("document"), 1_580_000_002, 987_654_321);
    let entries = snapshot::inventory_shared(&shared, true, 1024).unwrap();
    let ownership = snapshot::ownership(&shared, &entries).unwrap();
    fixture.plan.resources.push(PersistentResource {
        name: "files".into(),
        path: shared.clone(),
        kind: ResourceType::Directory,
    });
    let mut control = fixture.control();
    control.shared_paths = vec![shared.clone()];
    let journal = apply(&fixture.plan, &mut control).unwrap();
    assert_eq!(journal.shared_paths, vec![shared.clone()]);
    assert_eq!(
        snapshot::inventory_shared(&shared, true, 1024).unwrap(),
        entries
    );
    assert_eq!(snapshot::ownership(&shared, &entries).unwrap(), ownership);
    fs::write(shared.join("document"), b"new shared write").unwrap();
    control.active = false;
    assert_eq!(
        recover(&fixture.plan.work_directory, false, &mut control)
            .unwrap_err()
            .code,
        "RECOVERY_AUTHORIZATION_REQUIRED"
    );
    recover(&fixture.plan.work_directory, true, &mut control).unwrap();
    assert_eq!(
        snapshot::inventory_shared(&shared, true, 1024).unwrap(),
        entries
    );
    assert_eq!(snapshot::ownership(&shared, &entries).unwrap(), ownership);
}

fn posix_acl(owner: u16, named_user: u16, group: u16, mask: u16, other: u16) -> Vec<u8> {
    let mut bytes = 2u32.to_le_bytes().to_vec();
    for (tag, permission, id) in [
        (1u16, owner, u32::MAX),
        (2, named_user, 65534),
        (4, group, u32::MAX),
        (16, mask, u32::MAX),
        (32, other, u32::MAX),
    ] {
        bytes.extend(tag.to_le_bytes());
        bytes.extend(permission.to_le_bytes());
        bytes.extend(id.to_le_bytes());
    }
    bytes
}

fn set_posix_acl(path: &Path, name: &str, bytes: &[u8]) {
    let file = fs::File::open(path).unwrap();
    rustix::fs::fsetxattr(&file, name, bytes, rustix::fs::XattrFlags::empty()).unwrap();
}

fn set_mtime(path: &Path, seconds: i64, nanoseconds: i64) {
    let file = fs::File::open(path).unwrap();
    rustix::fs::futimens(
        &file,
        &rustix::fs::Timestamps {
            last_access: rustix::fs::Timespec {
                tv_sec: 0,
                tv_nsec: rustix::fs::UTIME_OMIT,
            },
            last_modification: rustix::fs::Timespec {
                tv_sec: seconds,
                tv_nsec: nanoseconds,
            },
        },
    )
    .unwrap();
}

#[test]
fn interrupted_shared_restore_preserves_nested_acls_and_clears_inherited_absence() {
    if rustix::process::geteuid().as_raw() != 0 {
        return;
    }
    use std::os::unix::process::CommandExt;
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let shared = directory.path().join("shared");
    let backup = directory.path().join("backup");
    for relative in ["", "nested", "plain"] {
        fs::create_dir(shared.join(relative)).unwrap();
        fs::set_permissions(shared.join(relative), fs::Permissions::from_mode(0o775)).unwrap();
    }
    fs::write(shared.join("nested/object"), b"ACL protected object").unwrap();
    fs::write(shared.join("plain/last-object"), b"plain object").unwrap();
    fs::set_permissions(
        shared.join("nested/object"),
        fs::Permissions::from_mode(0o660),
    )
    .unwrap();
    fs::set_permissions(
        shared.join("plain/last-object"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    for relative in ["", "nested", "nested/object"] {
        let file = fs::File::open(shared.join(relative)).unwrap();
        rustix::fs::fchown(
            &file,
            Some(rustix::process::Uid::from_raw(65533)),
            Some(rustix::process::Gid::from_raw(65533)),
        )
        .unwrap();
    }
    let root_acl = posix_acl(7, 7, 5, 7, 5);
    let nested_acl = posix_acl(7, 7, 0, 7, 0);
    set_posix_acl(&shared, "system.posix_acl_access", &root_acl);
    set_posix_acl(&shared, "system.posix_acl_default", &root_acl);
    set_posix_acl(
        &shared.join("nested"),
        "system.posix_acl_access",
        &nested_acl,
    );
    set_posix_acl(
        &shared.join("nested"),
        "system.posix_acl_default",
        &nested_acl,
    );
    set_posix_acl(
        &shared.join("nested/object"),
        "system.posix_acl_access",
        &posix_acl(6, 6, 0, 6, 0),
    );
    for (index, relative) in ["", "nested", "nested/object", "plain", "plain/last-object"]
        .into_iter()
        .enumerate()
    {
        set_mtime(
            &shared.join(relative),
            1_580_000_010 + index as i64,
            123_456_789 + index as i64,
        );
    }
    let entries = snapshot::inventory_shared(&shared, true, 4096).unwrap();
    let owners = snapshot::ownership(&shared, &entries).unwrap();
    assert!(owners.iter().any(|owner| !owner.access_acl.is_empty()));
    assert!(owners.iter().any(|owner| !owner.default_acl.is_empty()));
    assert!(
        owners
            .iter()
            .find(|owner| owner.path == Path::new("plain"))
            .unwrap()
            .access_acl
            .is_empty()
    );
    snapshot::snapshot(&shared, &backup, &entries).unwrap();
    // A missing later copy deterministically interrupts reconstruction after
    // rebuilding an ACL-bearing subtree. Recovery must accept that partial
    // tree and remove access/default ACLs inherited by the originally plain one.
    let held = directory.path().join("held-backup-object");
    fs::rename(backup.join("plain/last-object"), &held).unwrap();
    fs::write(shared.join("obsolete"), b"discard").unwrap();
    assert!(snapshot::restore_shared(&backup, &shared, &entries, 4096, &owners).is_err());
    assert!(shared.join("nested/object").exists());
    assert!(!shared.join("plain/last-object").exists());
    fs::rename(&held, backup.join("plain/last-object")).unwrap();
    for _ in 0..2 {
        snapshot::restore_shared(&backup, &shared, &entries, 4096, &owners).unwrap();
        assert_eq!(
            snapshot::inventory_shared(&shared, true, 4096).unwrap(),
            entries
        );
        assert_eq!(snapshot::ownership(&shared, &entries).unwrap(), owners);
    }
    let output = std::process::Command::new("/usr/bin/python3")
        .args(["-I", "-B", "-c", "import pathlib,sys; p=pathlib.Path(sys.argv[1]); assert p.read_bytes()==b'ACL protected object'; p.write_bytes(b'UID ACL write'); q=p.parent/'new-object'; q.write_bytes(b'default ACL write')"])
        .arg(shared.join("nested/object"))
        .uid(65534).gid(65534).output().unwrap();
    assert!(
        output.status.success(),
        "restored UID/default ACL access failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let new = shared.join("nested/new-object");
    let new_entries = snapshot::inventory_shared(&new, false, 4096).unwrap();
    assert!(
        !snapshot::ownership(&new, &new_entries).unwrap()[0]
            .access_acl
            .is_empty()
    );
}

#[test]
fn invalid_acl_metadata_is_rejected_before_replacing_shared_data() {
    if rustix::process::geteuid().as_raw() != 0 {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let shared = directory.path().join("shared");
    let backup = directory.path().join("backup");
    fs::create_dir(&shared).unwrap();
    fs::write(shared.join("object"), b"original").unwrap();
    let entries = snapshot::inventory_shared(&shared, true, 1024).unwrap();
    let owners = snapshot::ownership(&shared, &entries).unwrap();
    snapshot::snapshot(&shared, &backup, &entries).unwrap();
    let mut duplicated_user = posix_acl(7, 7, 5, 7, 5);
    let duplicate = duplicated_user[12..20].to_vec();
    duplicated_user.splice(20..20, duplicate);
    for invalid in [
        vec![0; 65537],
        vec![1, 2, 3, 4],
        posix_acl(8, 7, 5, 7, 5),
        duplicated_user,
        posix_acl(7, 7, 5, 7, 5),
    ] {
        let mut corrupted = owners.clone();
        corrupted[0].access_acl = invalid;
        fs::write(shared.join("object"), b"current data").unwrap();
        assert!(snapshot::restore_shared(&backup, &shared, &entries, 1024, &corrupted).is_err());
        assert_eq!(fs::read(shared.join("object")).unwrap(), b"current data");
    }
    let file_index = entries.iter().position(|entry| !entry.directory).unwrap();
    let mut corrupted = owners.clone();
    corrupted[file_index].default_acl = posix_acl(7, 7, 5, 7, 5);
    assert!(snapshot::restore_shared(&backup, &shared, &entries, 1024, &corrupted).is_err());
    assert_eq!(fs::read(shared.join("object")).unwrap(), b"current data");
    let mut value = serde_json::to_value(&owners[0]).unwrap();
    value.as_object_mut().unwrap().remove("access_acl");
    assert!(serde_json::from_value::<snapshot::Ownership>(value).is_err());
    let mut corrupted = owners.clone();
    corrupted[0].mtime_nanoseconds = 1_000_000_000;
    assert!(snapshot::restore_shared(&backup, &shared, &entries, 1024, &corrupted).is_err());
    assert_eq!(fs::read(shared.join("object")).unwrap(), b"current data");
}

#[test]
fn shared_permissions_cannot_relax_private_state_or_accept_aliases() {
    let fixture = Fixture::product("xczs");
    assert!(
        validate_shared_policy(
            std::slice::from_ref(&fixture.plan.data_dir),
            &fixture.plan,
            "xczs"
        )
        .is_err()
    );
    assert!(
        validate_shared_policy(
            &[fixture.plan.config.parent().unwrap().to_path_buf()],
            &fixture.plan,
            "xczs"
        )
        .is_err()
    );
    let shared = fixture._directory.path().join("shared");
    fs::create_dir(&shared).unwrap();
    fs::write(shared.join("file"), b"business").unwrap();
    os_symlink(Path::new("/etc/passwd"), &shared.join("alias"));
    assert!(snapshot::inventory_shared(&shared, true, 1024).is_err());
    fs::remove_file(shared.join("alias")).unwrap();
    os_link(&shared.join("file"), &shared.join("alias"));
    assert!(snapshot::inventory_shared(&shared, true, 1024).is_err());
}

fn os_symlink(source: &Path, target: &Path) {
    std::os::unix::fs::symlink(source, target).unwrap();
}
fn os_link(source: &Path, target: &Path) {
    fs::hard_link(source, target).unwrap();
}

#[test]
fn maintenance_capture_bounds_both_pipes_and_reaps_limit_or_timeout_children() {
    let directory = tempfile::tempdir().unwrap();
    for (mode, timeout) in [("flood", 3), ("timeout", 1)] {
        let pidfile = directory.path().join(mode);
        let source = "import os,sys,time,threading\nopen(sys.argv[1],'w').write(str(os.getpid()))\nif sys.argv[2]=='flood':\n def flood(fd):\n  while True: os.write(fd,b'private-secret'*8192)\n threading.Thread(target=flood,args=(2,),daemon=True).start()\n flood(1)\nelse: time.sleep(60)";
        let error = run_bounded(
            "/usr/bin/python3",
            &[
                "-c".into(),
                source.into(),
                pidfile.to_string_lossy().into_owned(),
                mode.into(),
            ],
            timeout,
        )
        .unwrap_err();
        assert!(!format!("{error:#}").contains("private-secret"));
        let pid = fs::read_to_string(pidfile).unwrap();
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
        assert!(format!("{error}").contains(if mode == "flood" {
            "output exceeds limit"
        } else {
            "timed out"
        }));
    }
}

#[test]
fn ready_http_requires_one_matching_product_identity() {
    for (headers, expected) in [
        ("x-service: test-product\r\n", true),
        ("X-Service: test-product\r\n", true),
        ("x-service: other-product\r\n", false),
        ("", false),
        (
            "x-service: test-product\r\nx-service: other-product\r\n",
            false,
        ),
        (
            "x-service: test-product\r\nx-service: test-product\r\n",
            false,
        ),
    ] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = [0u8; 1024];
            let read = socket.read(&mut request).unwrap();
            assert!(read > 0);
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\n{headers}Connection: close\r\n\r\n{{\"ready\":true}}"
                    )
                    .as_bytes(),
                )
                .unwrap();
        });
        assert_eq!(http_ready(address, "test-product").unwrap(), expected);
        server.join().unwrap();
    }
}

#[test]
fn service_observation_requires_a_loaded_stopped_unit_and_zero_main_pid() {
    for state in ["inactive", "failed"] {
        let report = format!("LoadState=loaded\nMainPID=0\nActiveState={state}\n");
        assert!(stopped_service_report(report.as_bytes()).unwrap());
    }
    for report in [
        "LoadState=not-found\nMainPID=0\nActiveState=inactive\n",
        "LoadState=error\nMainPID=0\nActiveState=inactive\n",
        "LoadState=loaded\nMainPID=17\nActiveState=inactive\n",
        "LoadState=loaded\nMainPID=0\nActiveState=activating\n",
        "LoadState=loaded\nMainPID=0\nActiveState=deactivating\n",
        "LoadState=loaded\nMainPID=0\nActiveState=unknown\n",
        "MainPID=0\nActiveState=inactive\n",
        "LoadState=loaded\nActiveState=inactive\n",
    ] {
        assert!(!stopped_service_report(report.as_bytes()).unwrap());
    }
    assert!(
        stopped_service_report(
            b"LoadState=loaded\nLoadState=not-found\nMainPID=0\nActiveState=inactive\n"
        )
        .is_err()
    );
}

// Native startup control tests use only this isolated declared product fixture.
pub(super) fn startup_fixture() -> (tempfile::TempDir, UpgradeJournal) {
    let fixture = Fixture::product("xcos");
    let mut control = fixture.control();
    control.fail_precheck_identity = true;
    apply(&fixture.plan, &mut control).unwrap_err();
    let mut journal = inspect(&fixture.plan.work_directory).unwrap();
    journal.phase = UpgradePhase::MaintenanceIntent;
    journal.plan.additional_services.push(AdditionalService {
        role: "mediamtx".into(),
        service: "xcos-mediamtx.service".into(),
    });
    journal
        .release
        .additional_service_roles
        .push("mediamtx".into());
    save(&journal).unwrap();
    (fixture._directory, journal)
}

// Collection tests retain the real verified payload and all completed backups.
pub(super) fn collection_fixture() -> (tempfile::TempDir, UpgradeJournal) {
    let fixture = Fixture::new();
    let mut control = fixture.control();
    let journal = apply(&fixture.plan, &mut control).unwrap();
    (fixture._directory, journal)
}

#[test]
fn runtime_lock_inode_survives_upgrade_and_authorized_recovery() {
    use std::os::fd::AsFd;
    let fixture = Fixture::new();
    let path = fixture.plan.data_dir.join(".state-instance.lock");
    let inode = fs::symlink_metadata(&path).unwrap().ino();
    let mut control = fixture.control();
    control.fail_start = true;
    assert!(apply(&fixture.plan, &mut control).is_err());
    assert_eq!(fs::symlink_metadata(&path).unwrap().ino(), inode);
    let journal = inspect(&fixture.plan.work_directory).unwrap();
    assert_eq!(journal.runtime_locks.len(), 1);
    assert!(
        journal
            .backups
            .iter()
            .flat_map(|b| &b.entries)
            .all(|entry| entry.path != Path::new(".state-instance.lock"))
    );
    control.fail_start = false;
    recover(&fixture.plan.work_directory, true, &mut control).unwrap();
    assert_eq!(fs::symlink_metadata(&path).unwrap().ino(), inode);
    let file = File::open(&path).unwrap();
    rustix::fs::flock(
        file.as_fd(),
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )
    .unwrap();
}
#[test]
fn restoration_preserves_nested_held_lock_and_rejects_second_open_description() {
    use std::os::fd::AsFd;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("data");
    let backup = temp.path().join("backup");
    snapshot::private_directory(&root).unwrap();
    snapshot::private_directory(&root.join("nested")).unwrap();
    let lock = root.join("nested/instance.lock");
    fs::write(&lock, b"").unwrap();
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(root.join("nested/state"), b"original").unwrap();
    let held = File::open(&lock).unwrap();
    let inode = held.metadata().unwrap().ino();
    rustix::fs::flock(
        held.as_fd(),
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )
    .unwrap();
    let excluded = vec![lock.clone()];
    let entries =
        snapshot::inventory_preserving(&root, true, 4096, true, false, &excluded).unwrap();
    let owners = snapshot::ownership(&root, &entries).unwrap();
    snapshot::snapshot(&root, &backup, &entries).unwrap();
    for _ in 0..2 {
        fs::write(root.join("nested/state"), b"new").unwrap();
        fs::write(root.join("extra"), b"remove").unwrap();
        snapshot::restore_preserving(
            &backup,
            &root,
            &entries,
            u64::MAX,
            &owners,
            false,
            snapshot::Preserved {
                files: &excluded,
                directories: &[],
            },
        )
        .unwrap();
        assert_eq!(fs::read(root.join("nested/state")).unwrap(), b"original");
        assert_eq!(fs::symlink_metadata(&lock).unwrap().ino(), inode);
        assert!(
            rustix::fs::flock(
                File::open(&lock).unwrap().as_fd(),
                rustix::fs::FlockOperation::NonBlockingLockExclusive
            )
            .is_err()
        );
    }
    drop(held);
    rustix::fs::flock(
        File::open(&lock).unwrap().as_fd(),
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )
    .unwrap();
}
#[test]
fn bounded_manager_children_receive_only_fixed_environment() {
    let bytes = run_bounded("/usr/bin/env", &[], 3).unwrap();
    let actual = std::str::from_utf8(&bytes)
        .unwrap()
        .lines()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual,
        BTreeSet::from(["PATH=/usr/bin:/bin", "LANG=C.UTF-8", "TZ=UTC"])
    );
}

#[test]
fn shared_directory_flock_preserves_inode_and_restores_all_business_contents() {
    use std::os::fd::AsFd;
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    let business = root.join("business");
    let backup = temporary.path().join("backup");
    snapshot::private_directory(&root).unwrap();
    snapshot::private_directory(&business).unwrap();
    fs::write(business.join("content"), b"original").unwrap();
    let held = File::open(&business).unwrap();
    let original_inode = held.metadata().unwrap().ino();
    rustix::fs::flock(
        held.as_fd(),
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )
    .unwrap();
    let entries = snapshot::inventory_preserving(&root, true, 4096, true, false, &[]).unwrap();
    let owners = snapshot::ownership(&root, &entries).unwrap();
    snapshot::snapshot(&root, &backup, &entries).unwrap();
    fs::write(business.join("content"), b"new write").unwrap();
    fs::write(business.join("extra"), b"new extra").unwrap();
    snapshot::restore_preserving(
        &backup,
        &root,
        &entries,
        u64::MAX,
        &owners,
        false,
        snapshot::Preserved {
            files: &[],
            directories: std::slice::from_ref(&business),
        },
    )
    .unwrap();
    assert_eq!(fs::read(business.join("content")).unwrap(), b"original");
    assert!(!business.join("extra").exists());
    assert_eq!(
        fs::symlink_metadata(&business).unwrap().ino(),
        original_inode
    );
    assert!(
        rustix::fs::flock(
            File::open(&business).unwrap().as_fd(),
            rustix::fs::FlockOperation::NonBlockingLockExclusive
        )
        .is_err()
    );
}
