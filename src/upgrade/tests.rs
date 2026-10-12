use super::*;
use std::os::unix::fs::PermissionsExt;

#[test]
fn coordinator_drop_unlocks_an_aliased_description_without_removing_its_inode() {
    use std::os::unix::fs::MetadataExt;
    let temporary = tempfile::tempdir().unwrap();
    let data = temporary.path().join("data");
    snapshot::private_directory(&data).unwrap();
    let lock = coordinator_lock(&data).unwrap();
    let alias = lock.file.file().try_clone().unwrap();
    let path = data.join(snapshot::COORDINATOR);
    let identity = fs::metadata(&path).unwrap().ino();
    assert!(coordinator_lock(&data).is_err());
    // Failed acquisition must not unlock the current owner.
    assert!(coordinator_lock(&data).is_err());
    drop(lock);
    let next = coordinator_lock(&data).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().ino(), identity);
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
    // Closing an alias to the previous description must not unlock this owner.
    drop(alias);
    assert!(coordinator_lock(&data).is_err());
    drop(next);
    assert!(coordinator_lock(&data).is_ok());
}

#[test]
fn state_lock_verification_failure_unlocks_only_the_original_description() {
    let temporary = tempfile::tempdir().unwrap();
    let data = temporary.path().join("data");
    snapshot::private_directory(&data).unwrap();
    let directory = PrivateStateDirectory::open(&data).unwrap();
    let file = directory.create_file(snapshot::COORDINATOR).unwrap();
    let alias = file.file().try_clone().unwrap();
    let original = data.join("original-coordinator");
    fs::rename(data.join(snapshot::COORDINATOR), &original).unwrap();
    directory.create_file(snapshot::COORDINATOR).unwrap();
    assert!(StateLock::acquire(file).is_err());
    let separately_opened = fs::File::open(original).unwrap();
    rustix::fs::flock(
        &separately_opened,
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )
    .unwrap();
    assert!(coordinator_lock(&data).is_ok());
    drop(alias);
}

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
        let output = std::process::Command::new(executable)
            .args([
                "--exact",
                "upgrade::tests::restore_read_only_directories_preserves_contents_modes_and_ownership",
                "--nocapture",
            ])
            .uid(65534)
            .gid(65534)
            .output()
            .unwrap();
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
        let entries = snapshot::inventory(&original, true, 4096, true).unwrap();
        let owners = snapshot::ownership(&original, &entries).unwrap();
        snapshot::snapshot(&original, &backup, &entries).unwrap();
        let gate = target.join(snapshot::PENDING);
        fs::write(&gate, b"pending gate").unwrap();
        let gate_inode = fs::metadata(&gate).unwrap().ino();
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
                assert_eq!(fs::metadata(&gate)?.ino(), gate_inode);
                assert_eq!(fs::read(&gate)?, b"pending gate");
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
    private_key: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let data = root.join("data");
        snapshot::private_directory(&data).unwrap();
        fs::write(data.join("config.json"), b"{\"current\":true}\n").unwrap();
        fs::write(data.join("business.txt"), b"business-before-upgrade").unwrap();
        snapshot::private_directory(&data.join("nested")).unwrap();
        fs::write(data.join("nested/object"), b"object-before-upgrade").unwrap();
        let private_key = root.join("signing.pem");
        let public_key = root.join("public.pem");
        run_bounded(
            "/usr/bin/openssl",
            &[
                "genpkey".into(),
                "-algorithm".into(),
                "ED25519".into(),
                "-out".into(),
                private_key.to_string_lossy().into_owned(),
            ],
            10,
        )
        .unwrap();
        run_bounded(
            "/usr/bin/openssl",
            &[
                "pkey".into(),
                "-in".into(),
                private_key.to_string_lossy().into_owned(),
                "-pubout".into(),
                "-out".into(),
                public_key.to_string_lossy().into_owned(),
            ],
            10,
        )
        .unwrap();
        let der = run_bounded(
            "/usr/bin/openssl",
            &[
                "pkey".into(),
                "-pubin".into(),
                "-in".into(),
                public_key.to_string_lossy().into_owned(),
                "-outform".into(),
                "DER".into(),
            ],
            10,
        )
        .unwrap();
        let installed = root.join("server");
        let target = root.join("new-server");
        snapshot::copy_regular(Path::new("/usr/bin/false"), &installed, 0o700).unwrap();
        snapshot::copy_regular(Path::new("/usr/bin/true"), &target, 0o700).unwrap();
        let schema =
            SchemaIdentity::new("test-product", "database-current", 1, "a".repeat(64)).unwrap();
        let release = UpgradeRelease {
            manifest_version: 1,
            source_identity: ReleaseIdentity {
                product: "test-product".into(),
                version: "1.0.0".into(),
                source_revision: "d".repeat(40),
                target: crate::FORMAL_RELEASE_TARGET.into(),
                state_contract_sha256: "e".repeat(64),
            },
            identity: ReleaseIdentity {
                product: "test-product".into(),
                version: "2.0.0".into(),
                source_revision: "b".repeat(40),
                target: crate::FORMAL_RELEASE_TARGET.into(),
                state_contract_sha256: "c".repeat(64),
            },
            binary_sha256: snapshot::digest_file(&target).unwrap(),
            source_schema: schema.clone(),
            target_schema: schema,
            artifact: None,
            additional_service_roles: Vec::new(),
            resources: vec![ReleaseResource {
                name: "data".into(),
                kind: ResourceType::Directory,
            }],
        };
        let plan = UpgradePlan {
            plan_version: 1,
            service: "test-product.service".into(),
            additional_services: Vec::new(),
            installed_binary: installed,
            target_binary: target,
            release_manifest: root.join("upgrade-release.json"),
            release_signature: root.join("upgrade-release.sig"),
            trusted_public_key: public_key,
            trusted_public_key_sha256: digest_hex(Sha256::digest(der)),
            config: data.join("config.json"),
            data_dir: data.clone(),
            resources: vec![PersistentResource {
                name: "data".into(),
                path: data,
                kind: ResourceType::Directory,
            }],
            work_directory: root.join("upgrade"),
            readiness_address: "127.0.0.1:12345".parse().unwrap(),
            timeout_seconds: 1,
            max_backup_bytes: 10_000_000,
            native_release: None,
        };
        let fixture = Self {
            _directory: directory,
            plan,
            release,
            private_key,
        };
        fixture.sign();
        fixture
    }

    fn sign(&self) {
        fs::write(
            &self.plan.release_manifest,
            serde_json::to_vec_pretty(&self.release).unwrap(),
        )
        .unwrap();
        run_bounded(
            "/usr/bin/openssl",
            &[
                "pkeyutl".into(),
                "-sign".into(),
                "-inkey".into(),
                self.private_key.to_string_lossy().into_owned(),
                "-rawin".into(),
                "-in".into(),
                self.plan.release_manifest.to_string_lossy().into_owned(),
                "-out".into(),
                self.plan.release_signature.to_string_lossy().into_owned(),
            ],
            10,
        )
        .unwrap();
    }

    fn use_complete_release(&mut self) {
        use std::os::unix::fs::symlink;
        let base = self._directory.path();
        let installation = base.join("install");
        let source = installation.join("releases/1.0.0");
        let target = base.join("download/install/releases/2.0.0");
        for (root, binary, body) in [
            (
                &source,
                &self.plan.installed_binary,
                b"original-web".as_slice(),
            ),
            (&target, &self.plan.target_binary, b"target-web".as_slice()),
        ] {
            fs::create_dir_all(root.join("bin")).unwrap();
            fs::create_dir_all(root.join("share")).unwrap();
            snapshot::copy_regular(binary, &root.join("bin/server"), 0o555).unwrap();
            fs::write(root.join("share/web"), body).unwrap();
            fs::set_permissions(root.join("share/web"), fs::Permissions::from_mode(0o444)).unwrap();
            for path in [root.clone(), root.join("bin"), root.join("share")] {
                fs::set_permissions(path, fs::Permissions::from_mode(0o555)).unwrap();
            }
        }
        fs::set_permissions(&installation, fs::Permissions::from_mode(0o755)).unwrap();
        let current = installation.join("current");
        symlink(&source, &current).unwrap();
        self.plan.installed_binary = current.join("bin/server");
        self.plan.target_binary = target.join("bin/server");
        self.plan.native_release = Some(NativeReleasePlan {
            current_link: current,
            source_root: source,
            install_root: installation.join("releases/2.0.0"),
        });
        let entries =
            snapshot::inventory(&target, true, self.plan.max_backup_bytes, false).unwrap();
        self.release.artifact = Some(ReleaseArtifact {
            protocol: "immutable-release-root-v1".into(),
            root_layout: "install/releases/2.0.0".into(),
            entrypoint: "bin/server".into(),
            tree_sha256: native_release::tree_digest(&entries).unwrap(),
            diagnostic_release_root_env: None,
        });
        self.sign();
    }

    fn control(&self) -> MockControl {
        MockControl {
            schema: self.release.source_schema.clone(),
            current_identity: self.release.source_identity.clone(),
            target_identity: self.release.identity.clone(),
            identity_calls: 0,
            active: false,
            active_services: BTreeSet::new(),
            fail_start: false,
            mutate_validator: false,
            validate_calls: 0,
            fail_target_validation: false,
            uncovered_state: None,
            delegated_probe: false,
            delegated_probe_complete: false,
        }
    }
}

#[test]
#[ignore = "child entry point for the administrator identity test"]
fn service_identity_probe() {
    assert_eq!(rustix::process::geteuid().as_raw(), 65534);
    assert_eq!(rustix::process::getegid().as_raw(), 65534);
    assert!(rustix::process::getgroups().unwrap().is_empty());
    let arguments: Vec<String> = std::env::args().collect();
    let path = &arguments[arguments.iter().position(|arg| arg == "--skip").unwrap() + 1];
    let value: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let data = Path::new(value["data_dir"].as_str().unwrap());
    assert!(
        PrivateStateDirectory::open(data)
            .unwrap()
            .try_maintenance_lock()
            .is_err()
    );
    let executable = std::env::current_exe().unwrap();
    let program = executable.as_path();
    assert_eq!(fs::metadata(program).unwrap().uid(), 0);
    assert_eq!(fs::metadata(data.join(PENDING)).unwrap().uid(), 65534);
    assert_eq!(
        fs::read(
            program
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("share/web")
        )
        .unwrap(),
        b"target-web"
    );
    assert!(fs::OpenOptions::new().write(true).open(program).is_err());
    assert!(fs::remove_file(value["current"].as_str().unwrap()).is_err());
    assert!(
        PrivateStateDirectory::open(data)
            .unwrap()
            .try_instance_lock()
            .is_err()
    );
}

#[test]
fn administrator_upgrade_delegates_to_real_service_identity_and_restores_ownership() {
    if rustix::process::geteuid().as_raw() != 0 {
        return;
    }
    let mut fixture = Fixture::new();
    fixture.plan.max_backup_bytes = 512 * 1024 * 1024;
    fs::set_permissions(&fixture.plan.config, fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(fixture._directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
    fixture.use_complete_release();
    let native = fixture.plan.native_release.clone().unwrap();
    fs::remove_file(&fixture.plan.target_binary).unwrap();
    snapshot::copy_regular(
        &std::env::current_exe().unwrap(),
        &fixture.plan.target_binary,
        0o555,
    )
    .unwrap();
    fixture.release.binary_sha256 = snapshot::digest_file(&fixture.plan.target_binary).unwrap();
    fixture.release.artifact.as_mut().unwrap().tree_sha256 = native_release::tree_digest(
        &snapshot::inventory(
            fixture
                .plan
                .target_binary
                .parent()
                .unwrap()
                .parent()
                .unwrap(),
            true,
            fixture.plan.max_backup_bytes,
            false,
        )
        .unwrap(),
    )
    .unwrap();
    fixture.sign();
    fs::write(
        fixture.plan.data_dir.join("probe.json"),
        serde_json::to_vec(
            &serde_json::json!({"data_dir":fixture.plan.data_dir,"current":native.current_link}),
        )
        .unwrap(),
    )
    .unwrap();
    fs::set_permissions(
        fixture.plan.data_dir.join("probe.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let entries = snapshot::inventory(
        &fixture.plan.data_dir,
        true,
        fixture.plan.max_backup_bytes,
        false,
    )
    .unwrap();
    let owners: Vec<_> = entries
        .iter()
        .map(|entry| snapshot::Ownership {
            path: entry.path.clone(),
            uid: 65534,
            gid: 65534,
        })
        .collect();
    snapshot::restore_ownership(&fixture.plan.data_dir, &entries, &owners).unwrap();
    assert!(PrivateStateDirectory::open(&fixture.plan.data_dir).is_err());
    let mut control = fixture.control();
    control.delegated_probe = true;
    let journal = apply(&fixture.plan, &mut control).unwrap();
    assert_eq!(journal.phase, UpgradePhase::Ready);
    assert!(journal.execution_seal.is_some());
    assert!(control.delegated_probe_complete);
    assert_eq!(
        fs::metadata(fixture.plan.data_dir.join(".state-maintenance.lock"))
            .unwrap()
            .uid(),
        65534
    );
    assert_eq!(fs::metadata(&native.current_link).unwrap().uid(), 0);
    assert_eq!(
        fs::metadata(&fixture.plan.work_directory).unwrap().mode() & 0o777,
        0o700
    );
    control.delegated_probe = false;
    control.active = false;
    assert_eq!(
        recover(&fixture.plan.work_directory, true, &mut control)
            .unwrap()
            .phase,
        UpgradePhase::RolledBack
    );
    assert_eq!(
        snapshot::inventory(
            &fixture.plan.data_dir,
            true,
            fixture.plan.max_backup_bytes,
            true
        )
        .unwrap(),
        entries
    );
    assert_eq!(
        snapshot::ownership(&fixture.plan.data_dir, &entries).unwrap(),
        owners
    );
    assert_eq!(
        fs::read_link(native.current_link).unwrap(),
        native.source_root
    );
}

#[test]
fn packaging_python_and_rust_bind_the_complete_tree_with_product_modes() {
    let mut fixture = Fixture::new();
    fixture.use_complete_release();
    let root = fixture
        .plan
        .target_binary
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    for path in [root.to_owned(), root.join("bin"), root.join("share")] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    fs::set_permissions(root.join("bin/server"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(root.join("share/web"), fs::Permissions::from_mode(0o644)).unwrap();
    let identity = fixture._directory.path().join("identity.json");
    let definition = fixture._directory.path().join("definition.json");
    fs::write(
        &identity,
        serde_json::to_vec(&fixture.release.identity).unwrap(),
    )
    .unwrap();
    let mut artifact = serde_json::to_value(fixture.release.artifact.as_ref().unwrap()).unwrap();
    artifact.as_object_mut().unwrap().remove("tree_sha256");
    fs::write(&definition, serde_json::to_vec(&serde_json::json!({
        "source_identity":fixture.release.source_identity, "source_schema":fixture.release.source_schema, "target_schema":fixture.release.target_schema,
        "resources":fixture.release.resources, "artifact":artifact,
    })).unwrap()).unwrap();
    fs::set_permissions(&fixture.private_key, fs::Permissions::from_mode(0o600)).unwrap();
    let output = fixture._directory.path().join("signed-output");
    run_bounded(
        "/usr/bin/python3",
        &[
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("scripts/stage-upgrade-release.py")
                .to_string_lossy()
                .into_owned(),
            "--binary".into(),
            fixture.plan.target_binary.to_string_lossy().into_owned(),
            "--release-root".into(),
            root.to_string_lossy().into_owned(),
            "--identity".into(),
            identity.to_string_lossy().into_owned(),
            "--definition".into(),
            definition.to_string_lossy().into_owned(),
            "--private-key".into(),
            fixture.private_key.to_string_lossy().into_owned(),
            "--trusted-public-key".into(),
            fixture
                .plan
                .trusted_public_key
                .to_string_lossy()
                .into_owned(),
            "--output".into(),
            output.to_string_lossy().into_owned(),
        ],
        20,
    )
    .unwrap();
    fixture.plan.release_manifest = output.join("upgrade-release.json");
    fixture.plan.release_signature = output.join("upgrade-release.sig");
    assert_eq!(
        apply(&fixture.plan, &mut fixture.control()).unwrap().phase,
        UpgradePhase::Ready
    );
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
fn release_paths_reject_lexical_aliases_and_dangling_selectors() {
    let mut fixture = Fixture::new();
    fixture.use_complete_release();
    let original = fixture.plan.clone();
    fixture.plan.target_binary = PathBuf::from(format!(
        "{}/./server",
        original.target_binary.parent().unwrap().display()
    ));
    assert!(validate_plan(&fixture.plan).is_err());
    fixture.plan = original;
    let native = fixture.plan.native_release.as_ref().unwrap();
    fs::remove_file(&native.current_link).unwrap();
    std::os::unix::fs::symlink(
        format!("{}/../1.0.0", native.source_root.display()),
        &native.current_link,
    )
    .unwrap();
    assert!(native_release::installed_binary(&fixture.plan).is_err());
    fs::remove_file(&native.current_link).unwrap();
    std::os::unix::fs::symlink(&native.source_root, &native.current_link).unwrap();
    std::os::unix::fs::symlink("missing", &native.install_root).unwrap();
    assert!(apply(&fixture.plan, &mut fixture.control()).is_err());
    assert!(!fixture.plan.data_dir.join(PENDING).exists());
}

#[test]
fn complete_release_switches_one_selector_and_restores_original_root_and_state() {
    let mut fixture = Fixture::new();
    fixture.use_complete_release();
    let native = fixture.plan.native_release.clone().unwrap();
    let original = snapshot::inventory(
        &native.source_root,
        true,
        fixture.plan.max_backup_bytes,
        false,
    )
    .unwrap();
    let mut control = fixture.control();
    let applied = apply(&fixture.plan, &mut control).unwrap();
    assert_eq!(applied.phase, UpgradePhase::Ready);
    assert_eq!(
        fs::read_link(&native.current_link).unwrap(),
        native.install_root
    );
    assert_eq!(
        fs::read(native.install_root.join("share/web")).unwrap(),
        b"target-web"
    );
    assert_eq!(
        snapshot::inventory(
            &native.source_root,
            true,
            fixture.plan.max_backup_bytes,
            false
        )
        .unwrap(),
        original
    );
    assert_eq!(
        inspect_status(&fixture.plan.work_directory)
            .unwrap()
            .installed_program,
        "target"
    );
    fs::write(
        fixture.plan.data_dir.join("business.txt"),
        b"target-written-data",
    )
    .unwrap();
    assert_eq!(
        recover(&fixture.plan.work_directory, false, &mut control)
            .unwrap_err()
            .code,
        "RECOVERY_AUTHORIZATION_REQUIRED"
    );
    // Keep damaged immutable assets as evidence and reconstruct the complete
    // original tree, rather than replacing only its executable.
    let web = native.source_root.join("share/web");
    fs::set_permissions(&web, fs::Permissions::from_mode(0o644)).unwrap();
    fs::write(&web, b"damaged-original-web").unwrap();
    fs::set_permissions(&web, fs::Permissions::from_mode(0o444)).unwrap();
    control.active = false;
    let recovered = recover(&fixture.plan.work_directory, true, &mut control).unwrap();
    assert_eq!(recovered.phase, UpgradePhase::RolledBack);
    assert_eq!(
        fs::read_link(&native.current_link).unwrap(),
        native.source_root
    );
    assert_eq!(
        snapshot::inventory(
            &native.source_root,
            true,
            fixture.plan.max_backup_bytes,
            false
        )
        .unwrap(),
        original
    );
    assert_eq!(
        fs::read(fixture.plan.data_dir.join("business.txt")).unwrap(),
        b"business-before-upgrade"
    );
    assert_eq!(
        inspect_status(&fixture.plan.work_directory)
            .unwrap()
            .installed_program,
        "original"
    );
    assert!(
        native
            .source_root
            .parent()
            .unwrap()
            .join(format!(
                ".upgrade-displaced-original-{}",
                recovered.operation_id
            ))
            .is_dir()
    );
}

#[test]
fn interrupted_complete_root_repair_resumes_without_using_an_unknown_selector() {
    use std::os::unix::fs::symlink;
    let mut fixture = Fixture::new();
    fixture.use_complete_release();
    let native = fixture.plan.native_release.clone().unwrap();
    let mut control = fixture.control();
    let mut journal = apply(&fixture.plan, &mut control).unwrap();
    journal.phase = UpgradePhase::RecoveryRestoring;
    journal
        .native_backup
        .as_mut()
        .unwrap()
        .source_recovery_started = true;
    save(&journal).unwrap();
    fs::remove_file(&native.current_link).unwrap();
    symlink(&native.source_root, &native.current_link).unwrap();
    let displaced = native.source_root.parent().unwrap().join(format!(
        ".upgrade-displaced-original-{}",
        journal.operation_id
    ));
    fs::rename(&native.source_root, &displaced).unwrap();
    control.active = false;
    let recovered = recover(&fixture.plan.work_directory, true, &mut control).unwrap();
    assert_eq!(recovered.phase, UpgradePhase::RolledBack);
    assert_eq!(
        fs::read(native.source_root.join("share/web")).unwrap(),
        b"original-web"
    );
    assert_eq!(
        fs::read_link(&native.current_link).unwrap(),
        native.source_root
    );
}

#[test]
fn complete_release_checksum_or_selector_drift_fails_before_data_mutation() {
    let mut fixture = Fixture::new();
    fixture.use_complete_release();
    let native = fixture.plan.native_release.clone().unwrap();
    let web = fixture
        .plan
        .target_binary
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("share/web");
    fs::set_permissions(&web, fs::Permissions::from_mode(0o644)).unwrap();
    fs::write(&web, b"changed-web").unwrap();
    fs::set_permissions(&web, fs::Permissions::from_mode(0o444)).unwrap();
    let mut control = fixture.control();
    assert!(apply(&fixture.plan, &mut control).is_err());
    assert!(!control.active);
    assert!(!fixture.plan.data_dir.join(PENDING).exists());
    assert_eq!(
        fs::read_link(&native.current_link).unwrap(),
        native.source_root
    );
    assert_eq!(
        fs::read(fixture.plan.data_dir.join("business.txt")).unwrap(),
        b"business-before-upgrade"
    );
}

/// Only service-manager/validator observations are simulated. Signatures,
/// immutable backups, binaries, paths, journals and lock interactions are real.
struct MockControl {
    schema: SchemaIdentity,
    current_identity: ReleaseIdentity,
    target_identity: ReleaseIdentity,
    identity_calls: usize,
    active: bool,
    active_services: BTreeSet<String>,
    fail_start: bool,
    mutate_validator: bool,
    validate_calls: usize,
    fail_target_validation: bool,
    uncovered_state: Option<PathBuf>,
    delegated_probe: bool,
    delegated_probe_complete: bool,
}

impl ServiceControl for MockControl {
    fn verify_release_identity(
        &mut self,
        _: &Path,
        plan: &UpgradePlan,
        expected: &ReleaseIdentity,
    ) -> anyhow::Result<()> {
        self.identity_calls += 1;
        let actual = if self.identity_calls == 1 {
            ensure!(
                !plan.data_dir.join(PENDING).exists(),
                "source check is late"
            );
            ensure!(!plan.work_directory.exists(), "source check is late");
            &self.current_identity
        } else {
            &self.target_identity
        };
        ensure!(
            actual == expected,
            "observed identity differs from authority"
        );
        Ok(())
    }
    fn is_stopped(&mut self, plan: &UpgradePlan) -> anyhow::Result<bool> {
        Ok(!self.active && !self.active_services.contains(&plan.service))
    }
    fn start(&mut self, plan: &UpgradePlan) -> anyhow::Result<()> {
        ensure!(
            !plan.data_dir.join(PENDING).exists(),
            "pending gate still exists"
        );
        let state = PrivateStateDirectory::open_for_administration(&plan.data_dir)?;
        let _lock = state.try_instance_lock()?;
        ensure!(!self.fail_start, "injected start failure");
        self.active = true;
        Ok(())
    }
    fn validate(
        &mut self,
        binary: &Path,
        plan: &UpgradePlan,
        _: Option<&ReleaseArtifact>,
    ) -> anyhow::Result<ValidatedState> {
        self.validate_calls += 1;
        ensure!(
            plan.data_dir.join(PENDING).exists(),
            "validation lacks pending gate"
        );
        ensure!(
            PrivateStateDirectory::open_for_administration(&plan.data_dir)?
                .try_instance_lock()
                .is_err(),
            "validation lacks exclusive maintenance"
        );
        if self.validate_calls == 2 {
            ensure!(
                binary == native_release::staged_binary(&inspect(&plan.work_directory)?)?,
                "target validation did not use sealed release"
            );
            ensure!(
                !self.fail_target_validation,
                "injected target-validation failure"
            );
            if self.delegated_probe {
                run_product(
                    binary,
                    plan,
                    &[
                        "--exact".into(),
                        "upgrade::tests::service_identity_probe".into(),
                        "--ignored".into(),
                        "--skip".into(),
                        plan.data_dir
                            .join("probe.json")
                            .to_string_lossy()
                            .into_owned(),
                    ],
                    30,
                )?;
                self.delegated_probe_complete = true;
            }
        }
        if self.mutate_validator && self.validate_calls == 2 {
            fs::write(
                plan.data_dir.join("business.txt"),
                b"unexpected-validator-write",
            )?;
        }
        Ok(ValidatedState {
            schema_identity: self.schema.clone(),
            state_paths: vec![
                plan.data_dir.clone(),
                plan.config.clone(),
                self.uncovered_state
                    .clone()
                    .unwrap_or_else(|| plan.data_dir.clone()),
            ],
        })
    }
    fn ready(&mut self, _: &UpgradePlan, _: &str, _: &str) -> anyhow::Result<bool> {
        Ok(self.active)
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
fn root_diagnostic_override_is_signed_narrow_and_derived_from_the_fixed_entrypoint() {
    let mut fixture = Fixture::new();
    fixture.use_complete_release();
    let mut artifact = fixture.release.artifact.clone().unwrap();
    artifact.diagnostic_release_root_env = Some("FIXTURE_RELEASE_ROOT".into());
    let binary = fixture.plan.target_binary.clone();
    let root = binary.parent().unwrap().parent().unwrap();
    let (name, derived) = native_release::diagnostic_environment(&binary, Some(&artifact))
        .unwrap()
        .unwrap();
    assert_eq!(derived, root);
    let probe = fixture._directory.path().join("probe/bin/server");
    fs::create_dir_all(probe.parent().unwrap()).unwrap();
    snapshot::copy_regular(Path::new("/usr/bin/env"), &probe, 0o700).unwrap();
    let environment = native_release::diagnostic_environment(&probe, Some(&artifact))
        .unwrap()
        .unwrap();
    let bytes = run_product_diagnostic(
        &probe,
        &fixture.plan,
        &[],
        5,
        Some((&environment.0, &environment.1)),
    )
    .unwrap();
    let values: BTreeSet<&str> = std::str::from_utf8(&bytes).unwrap().lines().collect();
    let root_variable = format!("{name}={}", environment.1.display());
    assert_eq!(
        values,
        BTreeSet::from(["PATH=/usr/bin:/bin", "LANG=C.UTF-8", root_variable.as_str()])
    );
    for name in [
        "PATH",
        "LD_PRELOAD",
        "bad_RELEASE_ROOT",
        "X_RELEASE_ROOT=invalid",
    ] {
        artifact.diagnostic_release_root_env = Some(name.into());
        assert!(native_release::diagnostic_environment(&binary, Some(&artifact)).is_err());
        fixture.release.artifact = Some(artifact.clone());
        fixture.sign();
        assert_eq!(
            verify_release(&fixture.plan).unwrap_err().code,
            "ARTIFACT_UNTRUSTED"
        );
        assert!(!fixture.plan.work_directory.exists());
    }
}

#[test]
fn incompatible_current_release_is_rejected_before_any_recovery_or_gate_write() {
    for field in ["version", "source_revision", "state_contract_sha256"] {
        let mut fixture = Fixture::new();
        let mut control = fixture.control();
        match field {
            "version" => fixture.release.source_identity.version = "0.9.0".into(),
            "source_revision" => fixture.release.source_identity.source_revision = "f".repeat(40),
            _ => fixture.release.source_identity.state_contract_sha256 = "f".repeat(64),
        }
        fixture.sign();
        let before = snapshot::inventory(&fixture.plan.data_dir, true, 10_000_000, false).unwrap();
        assert_eq!(
            apply(&fixture.plan, &mut control).unwrap_err().code,
            "CURRENT_RELEASE_INCOMPATIBLE"
        );
        assert_eq!(control.identity_calls, 1);
        assert!(!fixture.plan.work_directory.exists());
        assert!(!fixture.plan.data_dir.join(PENDING).exists());
        assert!(!fixture.plan.data_dir.join(".xssc.lock").exists());
        assert_eq!(
            snapshot::inventory(&fixture.plan.data_dir, true, 10_000_000, false).unwrap(),
            before
        );
        assert!(!control.active);
    }
}

#[test]
fn signed_same_structure_upgrade_preserves_state_and_hands_off_only_after_switch() {
    let fixture = Fixture::new();
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
    assert!(!fixture.plan.data_dir.join(PENDING).exists());
    assert_eq!(
        inspect(&fixture.plan.work_directory).unwrap().phase,
        UpgradePhase::Ready
    );
    assert_eq!(
        fs::metadata(fixture.plan.work_directory.join(JOURNAL))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn rejects_untrusted_or_wrong_platform_artifacts_before_creating_recovery_state() {
    let mut fixture = Fixture::new();
    let mut control = fixture.control();
    fs::write(&fixture.plan.release_signature, [0u8; 64]).unwrap();
    assert_eq!(
        apply(&fixture.plan, &mut control).unwrap_err().code,
        "ARTIFACT_UNTRUSTED"
    );
    assert!(!control.active);
    assert!(!fixture.plan.work_directory.exists());
    fixture.release.identity.target = "aarch64-unknown-linux-gnu".into();
    fixture.sign();
    assert_eq!(
        apply(&fixture.plan, &mut control).unwrap_err().code,
        "ARTIFACT_UNTRUSTED"
    );
    fixture.release.identity.target = crate::FORMAL_RELEASE_TARGET.into();
    fixture.sign();
    fixture.plan.trusted_public_key_sha256 = "0".repeat(64);
    assert_eq!(
        apply(&fixture.plan, &mut control).unwrap_err().code,
        "ARTIFACT_UNTRUSTED"
    );
}

#[test]
fn rejects_unsupported_conversion_without_relabeling_or_modifying_original_state() {
    let mut fixture = Fixture::new();
    let mut control = fixture.control();
    fixture.release.target_schema.schema_revision = 2;
    fixture.sign();
    assert_eq!(
        apply(&fixture.plan, &mut control).unwrap_err().code,
        "STATE_INCOMPATIBLE"
    );
    assert!(!control.active);
    assert!(!fixture.plan.work_directory.exists());
    assert_eq!(
        fs::read(fixture.plan.config).unwrap(),
        b"{\"current\":true}\n"
    );
}

#[test]
fn interrupted_validation_restores_program_configuration_and_data_then_restarts_original() {
    let fixture = Fixture::new();
    let original = snapshot::digest_file(&fixture.plan.installed_binary).unwrap();
    let mut control = fixture.control();
    control.fail_target_validation = true;
    apply(&fixture.plan, &mut control).unwrap_err();
    let interrupted = inspect(&fixture.plan.work_directory).unwrap();
    assert_eq!(interrupted.phase, UpgradePhase::BackupComplete);
    assert!(!interrupted.new_program_may_have_written);
    assert!(fixture.plan.data_dir.join(PENDING).exists());
    let restored = recover(&fixture.plan.work_directory, false, &mut control).unwrap();
    assert_eq!(restored.phase, UpgradePhase::RolledBack);
    assert!(control.active);
    assert_eq!(
        snapshot::digest_file(&fixture.plan.installed_binary).unwrap(),
        original
    );
    assert!(!fixture.plan.data_dir.join(PENDING).exists());
}

#[test]
fn detects_validator_side_effects_and_uses_verified_snapshot_for_recovery() {
    let fixture = Fixture::new();
    let mut control = fixture.control();
    control.mutate_validator = true;
    apply(&fixture.plan, &mut control).unwrap_err();
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
fn startup_failure_never_authorizes_discarding_new_writes_implicitly() {
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
fn recovery_start_interruption_also_protects_writes_before_a_second_restore() {
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
fn concurrent_instance_lock_prevents_backup_and_unknown_links_are_rejected() {
    let fixture = Fixture::new();
    let mut control = fixture.control();
    let state = PrivateStateDirectory::open(&fixture.plan.data_dir).unwrap();
    let instance = state.try_instance_lock().unwrap();
    apply(&fixture.plan, &mut control).unwrap_err();
    assert_eq!(
        inspect(&fixture.plan.work_directory).unwrap().phase,
        UpgradePhase::MaintenanceIntent
    );
    assert!(!fixture.plan.work_directory.join("original-binary").exists());
    instance.release().unwrap();
    recover(&fixture.plan.work_directory, false, &mut control).unwrap();
    let mut other = Fixture::new();
    std::os::unix::fs::symlink(
        other.plan.data_dir.join("business.txt"),
        other.plan.data_dir.join("unsafe-link"),
    )
    .unwrap();
    let mut control = other.control();
    assert!(apply(&other.plan, &mut control).is_err());
    assert_eq!(
        inspect(&other.plan.work_directory).unwrap().phase,
        UpgradePhase::BackupStarted
    );
    // Plan paths cannot point through a linked parent either.
    other.plan.config = other.plan.data_dir.join("unsafe-link");
    assert!(validate_plan(&other.plan).is_err());
}

#[test]
fn recovery_refuses_corrupt_backup_before_overwriting_current_state() {
    let fixture = Fixture::new();
    let mut control = fixture.control();
    control.fail_target_validation = true;
    apply(&fixture.plan, &mut control).unwrap_err();
    fs::write(
        fixture.plan.work_directory.join("resource-0/business.txt"),
        b"corrupt-backup",
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
fn product_external_state_must_be_covered_before_switch() {
    let fixture = Fixture::new();
    let mut control = fixture.control();
    control.uncovered_state = Some(fixture._directory.path().join("external-media"));
    let error = apply(&fixture.plan, &mut control).unwrap_err();
    assert_eq!(error.code, "UPGRADE_RESOURCE_COVERAGE_FAILED");
    assert_eq!(
        snapshot::digest_file(&fixture.plan.installed_binary).unwrap(),
        inspect(&fixture.plan.work_directory)
            .unwrap()
            .original_binary_sha256
    );
    assert_eq!(
        recover(&fixture.plan.work_directory, false, &mut control)
            .unwrap_err()
            .code,
        "RECOVERY_EXECUTION_FAILED"
    );
    assert!(!control.active);
    assert!(fixture.plan.data_dir.join(PENDING).exists());
    assert_eq!(
        fs::read(fixture.plan.data_dir.join("business.txt")).unwrap(),
        b"business-before-upgrade"
    );
}

#[test]
fn external_configuration_file_is_snapshotted_and_restored_with_the_original_program_and_tree() {
    let mut fixture = Fixture::new();
    let external = fixture._directory.path().join("external-config.json");
    fs::rename(&fixture.plan.config, &external).unwrap();
    fixture.plan.config = external.clone();
    fixture.plan.resources.insert(
        0,
        PersistentResource {
            name: "config".into(),
            path: external.clone(),
            kind: ResourceType::File,
        },
    );
    fixture.release.resources.insert(
        0,
        ReleaseResource {
            name: "config".into(),
            kind: ResourceType::File,
        },
    );
    fixture.sign();
    let before = fs::read(&external).unwrap();
    let mut control = fixture.control();
    control.fail_start = true;
    assert!(apply(&fixture.plan, &mut control).is_err());
    fs::write(&external, b"changed-after-target-start").unwrap();
    assert_eq!(
        recover(&fixture.plan.work_directory, false, &mut control)
            .unwrap_err()
            .code,
        "RECOVERY_AUTHORIZATION_REQUIRED"
    );
    assert_eq!(fs::read(&external).unwrap(), b"changed-after-target-start");
    control.fail_start = false;
    assert_eq!(
        recover(&fixture.plan.work_directory, true, &mut control)
            .unwrap()
            .phase,
        UpgradePhase::RolledBack
    );
    assert_eq!(fs::read(&external).unwrap(), before);
    assert_eq!(
        fs::read(fixture.plan.data_dir.join("business.txt")).unwrap(),
        b"business-before-upgrade"
    );
    assert_eq!(
        snapshot::digest_file(&fixture.plan.installed_binary).unwrap(),
        snapshot::digest_file(Path::new("/usr/bin/false")).unwrap()
    );
}

#[test]
fn offline_tool_refuses_running_servers_before_journal_or_gate_and_rechecks_recovery() {
    let fixture = Fixture::new();
    let mut control = fixture.control();
    control.active = true;
    let original = fs::read(&fixture.plan.installed_binary).unwrap();
    let config = fs::read(&fixture.plan.config).unwrap();
    assert_eq!(
        apply(&fixture.plan, &mut control).unwrap_err().code,
        "SERVER_MUST_BE_STOPPED"
    );
    assert!(control.active);
    assert!(!fixture.plan.work_directory.exists());
    assert!(!fixture.plan.data_dir.join(PENDING).exists());
    assert_eq!(fs::read(&fixture.plan.installed_binary).unwrap(), original);
    assert_eq!(fs::read(&fixture.plan.config).unwrap(), config);
    // The operator stops the service before invoking the auxiliary tool.
    control.active = false;
    apply(&fixture.plan, &mut control).unwrap();
    fs::write(
        fixture.plan.data_dir.join("business.txt"),
        b"new-business-write",
    )
    .unwrap();
    assert_eq!(
        recover(&fixture.plan.work_directory, true, &mut control)
            .unwrap_err()
            .code,
        "SERVER_MUST_BE_STOPPED"
    );
    assert!(control.active);
    assert_eq!(
        fs::read(fixture.plan.data_dir.join("business.txt")).unwrap(),
        b"new-business-write"
    );
    control.active = false;
    assert_eq!(
        recover(&fixture.plan.work_directory, true, &mut control)
            .unwrap()
            .phase,
        UpgradePhase::RolledBack
    );
}

#[test]
fn signed_additional_writer_mapping_cannot_be_omitted_or_snapshot_an_active_companion() {
    let mut fixture = Fixture::new();
    fixture.release.additional_service_roles = vec!["recording-writer".into()];
    fixture.sign();
    let mut control = fixture.control();
    assert_eq!(
        apply(&fixture.plan, &mut control).unwrap_err().code,
        "ARTIFACT_UNTRUSTED"
    );
    assert!(!fixture.plan.work_directory.exists());
    fixture.plan.additional_services = vec![AdditionalService {
        role: "recording-writer".into(),
        service: "fixture-recordings.service".into(),
    }];
    control
        .active_services
        .insert("fixture-recordings.service".into());
    assert_eq!(
        apply(&fixture.plan, &mut control).unwrap_err().code,
        "SERVER_MUST_BE_STOPPED"
    );
    assert!(!control.active);
    assert!(!fixture.plan.work_directory.exists());
    assert!(!fixture.plan.data_dir.join(PENDING).exists());
    control.active_services.clear();
    assert_eq!(
        apply(&fixture.plan, &mut control).unwrap().phase,
        UpgradePhase::Ready
    );
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
