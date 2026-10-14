use std::path::PathBuf;

use clap::{Parser, Subcommand};
use xssc::{Product, support_matrix};

#[derive(Debug, Parser)]
#[command(
    name = "xssc",
    version,
    about = "Verify current releases offline, apply upgrades, and recover the complete program, configuration and persistent data group."
)]
struct Cli {
    #[arg(long, global = true)]
    tool_lock_fd: Option<i32>,
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

/// Upgrade current managed releases and recover the complete protected group.
#[derive(Debug, Subcommand)]
enum Command {
    /// Upgrade a verified release under durable startup control after verifying all verified inputs.
    ApplyUpgrade {
        #[arg(long)]
        plan: PathBuf,
    },
    /// Inspect durable phases and verify completed backups.
    InspectUpgrade {
        #[arg(long)]
        work_directory: PathBuf,
    },
    /// Recover the original release, configuration and persistent data together.
    RecoverUpgrade {
        #[arg(long)]
        work_directory: PathBuf,
        /// Authorize discarding writes after a program received run ownership.
        #[arg(long)]
        allow_data_loss: bool,
    },
    /// Plan or explicitly collect closed upgrade materials under an authorized retention policy.
    CollectUpgrades {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        minimum_age_seconds: u64,
        #[arg(long)]
        keep_completed: usize,
        #[arg(long)]
        execute: bool,
        #[arg(long)]
        resume_collection: Option<uuid::Uuid>,
    },
    /// Show the currently supported products and their upgrade and recovery capabilities.
    Support,
    /// Show each product's current maintenance contract and runtime-state requirements.
    Catalog,
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            let value = match error.downcast_ref::<xssc::upgrade::UpgradeFailure>() {
                Some(error) => serde_json::json!({"error": error}),
                None => {
                    serde_json::json!({"error": {"code": "MAINTENANCE_FAILED", "message": "Offline maintenance failed; check the current operation contract, file permissions and supported scope."}})
                }
            };
            println!("{value}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let mut control = xssc::upgrade::SystemdControl::with_tool_lock(cli.tool_lock_fd)?;
    match cli.command {
        Command::ApplyUpgrade { plan } => {
            let plan = xssc::upgrade::read_plan(&plan)?;
            let result = xssc::upgrade::apply(&plan, &mut control)?;
            print_transaction(&result, "upgrade_complete");
            Ok(())
        }
        Command::InspectUpgrade { work_directory } => {
            let result = xssc::upgrade::inspect_coordinated(&work_directory, &mut control)?;
            println!(
                "{}",
                serde_json::json!({
                    "operation_id":result.journal.operation_id,"phase":result.journal.phase,
                    "product":result.journal.release.identity.product,"work_directory":result.journal.plan.work_directory,
                    "installed_program":result.installed_program,"installed_binary_sha256":result.installed_binary_sha256,
                    "persistent_state_verification":result.persistent_state_verification,
                    "backup_complete":result.journal.backup_complete,
                    "new_program_may_have_written":result.journal.new_program_may_have_written,
                    "recovered_program_may_have_written":result.journal.recovered_program_may_have_written,
                })
            );
            Ok(())
        }
        Command::RecoverUpgrade {
            work_directory,
            allow_data_loss,
        } => {
            let result = xssc::upgrade::recover(&work_directory, allow_data_loss, &mut control)?;
            print_transaction(&result, "recovery_complete");
            Ok(())
        }
        Command::CollectUpgrades {
            root,
            minimum_age_seconds,
            keep_completed,
            execute,
            resume_collection,
        } => {
            let result = xssc::upgrade::collection::collect(
                &root,
                xssc::upgrade::collection::RetentionPolicy {
                    minimum_age_seconds,
                    keep_completed,
                },
                execute,
                resume_collection,
                &mut control,
            )?;
            println!("{result}");
            Ok(())
        }
        Command::Support => print_support(cli.json),
        Command::Catalog => print_catalog(cli.json),
    }
}

fn print_transaction(result: &xssc::upgrade::UpgradeJournal, status: &str) {
    println!(
        "{}",
        serde_json::json!({
            "operation_id":result.operation_id,"phase":result.phase,"status":status,
            "product":result.release.identity.product,"version":if status=="recovery_complete" {&result.release.source_identity.version}else{&result.release.identity.version},
            "work_directory":result.plan.work_directory,"backup_complete":result.backup_complete,
        })
    );
}

fn print_support(json: bool) -> anyhow::Result<()> {
    let matrix = support_matrix();
    if json {
        println!("{}", serde_json::to_string_pretty(&matrix)?);
    } else {
        for product in matrix.products {
            println!(
                "{}\tupgrade={}\trecovery={}",
                product.product, product.release_upgrade, product.durable_recovery
            );
        }
    }
    Ok(())
}

fn print_catalog(json: bool) -> anyhow::Result<()> {
    let entries = Product::ALL
        .into_iter()
        .map(Product::contract)
        .collect::<Vec<_>>();
    if json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
    } else {
        for entry in entries {
            println!("{}\truntime={}", entry.product, entry.has_runtime_state);
        }
    }
    Ok(())
}
