//! Bounded child processes and explicit administrator descriptor inheritance.
//!
//! No child output or unsafe process setup belongs to the upgrade state machine.

use std::{
    io::Read,
    os::unix::fs::MetadataExt,
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, ensure};

use super::{MAX_JSON, UpgradePlan, execution, snapshot};

pub(super) fn run_bounded(
    program: impl AsRef<Path>,
    arguments: &[String],
    timeout: u64,
) -> anyhow::Result<Vec<u8>> {
    run_bounded_command(program.as_ref(), arguments, timeout, false, None, &[])
}

#[allow(unsafe_code)] // F_DUPFD_CLOEXEC creates an owned valid descriptor atomically.
pub(super) fn duplicate_inherited_file(descriptor: i32) -> anyhow::Result<std::fs::File> {
    use std::os::fd::FromRawFd;
    ensure!(
        (3..1_048_576).contains(&descriptor),
        "invalid tool lock descriptor"
    );
    let duplicate = unsafe { libc::fcntl(descriptor, libc::F_DUPFD_CLOEXEC, 64) };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { std::fs::File::from_raw_fd(duplicate) })
}

pub(super) fn run_product(
    program: &Path,
    plan: &UpgradePlan,
    arguments: &[String],
    timeout: u64,
    tool_lock: std::os::fd::BorrowedFd<'_>,
    instances: &[(std::path::PathBuf, std::fs::File)],
) -> anyhow::Result<Vec<u8>> {
    let (uid, gid) = execution::identity(plan)?;
    let mut arguments = arguments.to_vec();
    arguments.extend([
        "--service-uid".into(),
        uid.to_string(),
        "--service-gid".into(),
        gid.to_string(),
        "--tool-lock-fd".into(),
        "5".into(),
    ]);
    for (index, (path, _)) in instances.iter().enumerate() {
        arguments.extend([
            "--instance-lock-fd".into(),
            format!("{}={}", path.display(), 6 + index),
        ]);
    }
    ensure!(
        rustix::process::geteuid().as_raw() == 0,
        "product maintenance requires administrator execution"
    );
    run_bounded_command(
        program,
        &arguments,
        timeout,
        true,
        Some(tool_lock),
        instances,
    )
}

#[allow(unsafe_code)] // Only the documented post-fork descriptor boundary.
fn run_bounded_command(
    program: &Path,
    arguments: &[String],
    timeout: u64,
    sealed: bool,
    tool_lock: Option<std::os::fd::BorrowedFd<'_>>,
    instances: &[(std::path::PathBuf, std::fs::File)],
) -> anyhow::Result<Vec<u8>> {
    use std::os::{
        fd::{AsFd, AsRawFd},
        unix::process::CommandExt,
    };
    let executable = if sealed {
        let file = snapshot::open_regular(program)?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.mode() & 0o7022 == 0 && metadata.mode() & 0o111 != 0,
            "product executable has unsafe permissions"
        );
        ensure!(
            metadata.uid() == 0,
            "sealed executable must be administrator controlled"
        );
        execution::require_trusted(program.parent().context("program parent missing")?)?;
        Some(rustix::io::fcntl_dupfd_cloexec(&file, 64)?)
    } else {
        None
    };
    let mut command = Command::new(if executable.is_some() {
        Path::new("/proc/self/fd/4")
    } else {
        program
    });
    if executable.is_some() {
        command.arg0(program);
    }
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .env("TZ", "UTC")
        .process_group(0)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let executable_fd = executable.as_ref().map(AsRawFd::as_raw_fd);
    let tool_file = tool_lock
        .map(|descriptor| rustix::io::fcntl_dupfd_cloexec(descriptor, 64))
        .transpose()?;
    let tool_fd = tool_file.as_ref().map(AsRawFd::as_raw_fd);
    let instance_files = instances
        .iter()
        .map(|(_, file)| rustix::io::fcntl_dupfd_cloexec(file, 128))
        .collect::<Result<Vec<_>, _>>()?;
    let instance_fds = instance_files
        .iter()
        .map(AsRawFd::as_raw_fd)
        .collect::<Vec<_>>();
    // SAFETY: the parent holds the verified executable descriptor until spawn
    // returns. After fork this closure performs only fixed descriptor and
    // descriptor syscalls; it acquires no locks and allocates no storage.
    // Helpers retain administrator identity; service UID/GID are explicit data parameters.
    unsafe {
        command.pre_exec(move || {
            if let Some(source) = executable_fd
                && (libc::dup2(source, 4) < 0 || libc::fcntl(4, libc::F_SETFD, 0) < 0)
            {
                return Err(std::io::Error::last_os_error());
            }
            if let Some(source) = tool_fd
                && (libc::dup2(source, 5) < 0 || libc::fcntl(5, libc::F_SETFD, 0) < 0)
            {
                return Err(std::io::Error::last_os_error());
            }
            for (index, source) in instance_fds.iter().enumerate() {
                let target = 6 + index as i32;
                if libc::dup2(*source, target) < 0 || libc::fcntl(target, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let mut process = command
        .spawn()
        .context("cannot execute maintenance command")?;
    let mut stdout = process
        .stdout
        .take()
        .context("maintenance stdout missing")?;
    let mut stderr = process
        .stderr
        .take()
        .context("maintenance stderr missing")?;
    for descriptor in [stdout.as_fd(), stderr.as_fd()] {
        if let Err(error) = rustix::fs::fcntl_getfl(descriptor).and_then(|flags| {
            rustix::fs::fcntl_setfl(descriptor, flags | rustix::fs::OFlags::NONBLOCK)
        }) {
            let _ = process.kill();
            let _ = process.wait();
            return Err(std::io::Error::from(error).into());
        }
    }
    let deadline = Instant::now() + Duration::from_secs(timeout);
    let mut output = Vec::new();
    let mut errors = Vec::new();
    let (mut stdout_closed, mut stderr_closed) = (false, false);
    let mut status = None;
    let result = (|| -> anyhow::Result<Vec<u8>> {
        loop {
            ensure!(Instant::now() < deadline, "maintenance command timed out");
            read_pipe(&mut stdout, &mut output, &mut stdout_closed)?;
            read_pipe(&mut stderr, &mut errors, &mut stderr_closed)?;
            ensure!(
                output.len() as u64 <= MAX_JSON && errors.len() as u64 <= MAX_JSON,
                "maintenance command output exceeds limit"
            );
            if status.is_none() {
                status = process.try_wait()?;
            }
            if status.is_some() && stdout_closed && stderr_closed {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        let status = status.context("maintenance status missing")?;
        // Product stderr can contain credentials. Never reflect it publicly.
        ensure!(
            status.success(),
            "maintenance command failed with exit code {:?}",
            status.code()
        );
        Ok(output)
    })();
    if result.is_err() {
        if let Some(pid) = rustix::process::Pid::from_raw(process.id() as i32) {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        }
        let _ = process.kill();
        let _ = process.wait();
    }
    result
}

fn read_pipe(reader: &mut impl Read, bytes: &mut Vec<u8>, closed: &mut bool) -> anyhow::Result<()> {
    if *closed {
        return Ok(());
    }
    let mut buffer = [0u8; 16384];
    let remaining = (MAX_JSON + 1).saturating_sub(bytes.len() as u64) as usize;
    if remaining == 0 {
        return Ok(());
    }
    let limit = remaining.min(buffer.len());
    match reader.read(&mut buffer[..limit]) {
        Ok(0) => *closed = true,
        Ok(count) => bytes.extend_from_slice(&buffer[..count]),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}
