//! Synapse Build Automation (xtask)
//!
//! This binary provides build automation for the Synapse project.
//! It handles the complexity of building eBPF programs cross-platform.
//!
//! # Commands
//!
//! - `build-ebpf`: Compile synapse-ebpf to eBPF bytecode
//! - `codegen`: Generate kernel struct bindings
//! - `dist`: Create release artifacts
//!
//! # Cross-Platform Strategy
//!
//! eBPF programs require Linux to build. For Windows/macOS developers:
//!
//! 1. Check if running on Linux → build natively
//! 2. Otherwise → use Docker container with Aya toolchain
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      xtask build-ebpf                            │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                  │
//! │  ┌──────────────┐                                               │
//! │  │  Host OS?    │                                               │
//! │  └──────┬───────┘                                               │
//! │         │                                                        │
//! │    ┌────┴────┐                                                  │
//! │    │         │                                                  │
//! │  Linux    Windows/macOS                                         │
//! │    │         │                                                  │
//! │    ▼         ▼                                                  │
//! │  Native   Docker Container                                      │
//! │  Build    (aya-bpf-builder)                                     │
//! │    │         │                                                  │
//! │    └────┬────┘                                                  │
//! │         │                                                        │
//! │         ▼                                                        │
//! │  target/bpfel-unknown-none/release/synapse-ebpf                 │
//! │                                                                  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use owo_colors::OwoColorize;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Synapse build automation
#[derive(Parser)]
#[command(name = "xtask", about = "Synapse build automation")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build eBPF programs (uses Docker on non-Linux platforms)
    BuildEbpf {
        /// Build in release mode
        #[arg(long, default_value = "true")]
        release: bool,
    },

    /// Generate kernel struct bindings via aya-tool
    Codegen {
        /// Path to vmlinux or BTF file (optional, uses system default)
        #[arg(long)]
        btf: Option<PathBuf>,
    },

    /// Create release distribution artifacts
    Dist {
        /// Target platform (linux-x86_64, linux-aarch64)
        #[arg(long, default_value = "linux-x86_64")]
        target: String,
    },

    /// Run all CI checks
    Ci,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::BuildEbpf { release } => build_ebpf(release),
        Commands::Codegen { btf } => codegen(btf),
        Commands::Dist { target } => dist(&target),
        Commands::Ci => ci(),
    }
}

/// Build eBPF programs, using Docker on non-Linux platforms
fn build_ebpf(release: bool) -> Result<()> {
    let workspace_root = workspace_root()?;
    let ebpf_dir = workspace_root.join("synapse-ebpf");

    println!("{} eBPF programs...", "Building".green().bold());

    if cfg!(target_os = "linux") {
        // Native Linux build
        println!("  {} Native Linux build", "→".cyan());
        build_ebpf_native(&ebpf_dir, release)?;
    } else {
        // Docker-based build for Windows/macOS
        println!("  {} Cross-platform build via Docker", "→".cyan());
        build_ebpf_docker(&workspace_root, release)?;
    }

    let output_path = workspace_root
        .join("target")
        .join("bpfel-unknown-none")
        .join(if release { "release" } else { "debug" })
        .join("synapse-ebpf");

    println!(
        "{} eBPF bytecode: {}",
        "✓".green().bold(),
        output_path.display()
    );

    Ok(())
}

/// Native Linux build using cargo + bpf-linker
fn build_ebpf_native(ebpf_dir: &Path, release: bool) -> Result<()> {
    // Check for bpf-linker
    if which::which("bpf-linker").is_err() {
        println!("  {} bpf-linker not found. Installing...", "!".yellow());
        let status = Command::new("cargo")
            .args(["install", "bpf-linker"])
            .status()
            .context("Failed to install bpf-linker")?;

        if !status.success() {
            bail!("Failed to install bpf-linker");
        }
    }

    // Build eBPF crate
    let mut cmd = Command::new("cargo");
    cmd.current_dir(ebpf_dir);
    cmd.env("CARGO_CFG_BPF_TARGET_ARCH", "x86_64");

    // Use +nightly for eBPF builds (required for build-std)
    cmd.arg("+nightly");
    cmd.args([
        "build",
        "--target",
        "bpfel-unknown-none",
        "-Z",
        "build-std=core",
    ]);

    if release {
        cmd.arg("--release");
    }

    let status = cmd.status().context("Failed to run cargo build")?;

    if !status.success() {
        bail!("eBPF build failed");
    }

    Ok(())
}

/// Docker-based build for Windows/macOS developers
fn build_ebpf_docker(workspace_root: &Path, release: bool) -> Result<()> {
    // Check for Docker
    if which::which("docker").is_err() {
        bail!(
            "Docker not found. Please install Docker Desktop to build eBPF programs on {}.",
            std::env::consts::OS
        );
    }

    let docker_image = "ghcr.io/aya-rs/aya-bpf-builder:latest";

    println!("  {} Using Docker image: {}", "→".cyan(), docker_image);

    // Pull the image if not present
    let pull_status = Command::new("docker")
        .args(["pull", docker_image])
        .status()
        .context("Failed to pull Docker image")?;

    if !pull_status.success() {
        println!(
            "  {} Failed to pull image, trying local cache...",
            "!".yellow()
        );
    }

    // Run the build inside Docker
    let workspace_str = workspace_root.to_string_lossy();
    let volume_mount = format!("{}:/workspace", workspace_str);
    let mut docker_args = vec![
        "run",
        "--rm",
        "-v",
        &volume_mount,
        "-w",
        "/workspace/synapse-ebpf",
        docker_image,
        "cargo",
        "+nightly",
        "build",
        "--target",
        "bpfel-unknown-none",
        "-Z",
        "build-std=core",
    ];

    if release {
        docker_args.push("--release");
    }

    let status = Command::new("docker")
        .args(&docker_args)
        .status()
        .context("Failed to run Docker build")?;

    if !status.success() {
        bail!("Docker eBPF build failed");
    }

    Ok(())
}

/// Generate kernel struct bindings using aya-tool
fn codegen(btf_path: Option<PathBuf>) -> Result<()> {
    println!("{} kernel bindings...", "Generating".green().bold());

    // Check for aya-tool
    if which::which("aya-tool").is_err() {
        println!("  {} aya-tool not found. Installing...", "!".yellow());
        let status = Command::new("cargo")
            .args(["install", "aya-tool"])
            .status()
            .context("Failed to install aya-tool")?;

        if !status.success() {
            bail!("Failed to install aya-tool");
        }
    }

    let workspace_root = workspace_root()?;
    let output_path = workspace_root
        .join("synapse-ebpf")
        .join("src")
        .join("bindings.rs");

    // Kernel structs we need for attestation
    let structs = [
        "task_struct",
        "cgroup",
        "css_set",
        "kernfs_node",
        "vm_area_struct",
        "file",
        "path",
        "dentry",
        "sock",
        "sk_buff",
    ];

    let mut cmd = Command::new("aya-tool");
    cmd.arg("generate");

    // Add BTF source if specified
    if let Some(btf) = btf_path {
        cmd.arg("--btf").arg(btf);
    }

    // Add struct names
    for s in &structs {
        cmd.arg(s);
    }

    let output = cmd.output().context("Failed to run aya-tool")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("aya-tool failed: {}", stderr);
    }

    // Write bindings to file
    std::fs::write(&output_path, &output.stdout).context("Failed to write bindings file")?;

    println!(
        "{} Bindings written to: {}",
        "✓".green().bold(),
        output_path.display()
    );

    Ok(())
}

/// Create release distribution artifacts
fn dist(target: &str) -> Result<()> {
    println!(
        "{} distribution for {}...",
        "Creating".green().bold(),
        target
    );

    let workspace_root = workspace_root()?;

    // Build release binaries
    println!("  {} Building release binaries...", "→".cyan());

    let status = Command::new("cargo")
        .current_dir(&workspace_root)
        .args(["build", "--release", "--workspace"])
        .status()
        .context("Failed to build release")?;

    if !status.success() {
        bail!("Release build failed");
    }

    // Build eBPF
    println!("  {} Building eBPF programs...", "→".cyan());
    build_ebpf(true)?;

    // Create dist directory
    let dist_dir = workspace_root.join("dist").join(target);
    std::fs::create_dir_all(&dist_dir).context("Failed to create dist directory")?;

    // Copy binaries
    let binaries = ["syn-proxy", "syn"];
    for bin in &binaries {
        let src = workspace_root
            .join("target")
            .join("release")
            .join(if cfg!(windows) {
                format!("{}.exe", bin)
            } else {
                bin.to_string()
            });

        let dst = dist_dir.join(if cfg!(windows) {
            format!("{}.exe", bin)
        } else {
            bin.to_string()
        });

        if src.exists() {
            std::fs::copy(&src, &dst).context("Failed to copy binary")?;
            println!("  {} Copied {}", "✓".green(), bin);
        }
    }

    // Copy eBPF bytecode
    let ebpf_src = workspace_root
        .join("target")
        .join("bpfel-unknown-none")
        .join("release")
        .join("synapse-ebpf");

    if ebpf_src.exists() {
        let ebpf_dst = dist_dir.join("synapse-ebpf.o");
        std::fs::copy(&ebpf_src, &ebpf_dst).context("Failed to copy eBPF bytecode")?;
        println!("  {} Copied synapse-ebpf.o", "✓".green());
    }

    println!(
        "{} Distribution created: {}",
        "✓".green().bold(),
        dist_dir.display()
    );

    Ok(())
}

/// Run all CI checks
fn ci() -> Result<()> {
    println!("{} CI checks...", "Running".green().bold());

    let workspace_root = workspace_root()?;

    // Check formatting
    println!("  {} cargo fmt --check", "→".cyan());
    let status = Command::new("cargo")
        .current_dir(&workspace_root)
        .args(["fmt", "--check"])
        .status()?;

    if !status.success() {
        bail!("Formatting check failed");
    }

    // Run clippy
    println!("  {} cargo clippy", "→".cyan());
    let status = Command::new("cargo")
        .current_dir(&workspace_root)
        .args(["clippy", "--workspace", "--", "-D", "warnings"])
        .status()?;

    if !status.success() {
        bail!("Clippy check failed");
    }

    // Run tests
    println!("  {} cargo test", "→".cyan());
    let status = Command::new("cargo")
        .current_dir(&workspace_root)
        .args(["test", "--workspace"])
        .status()?;

    if !status.success() {
        bail!("Tests failed");
    }

    println!("{} All CI checks passed!", "✓".green().bold());

    Ok(())
}

/// Get the workspace root directory
fn workspace_root() -> Result<PathBuf> {
    let output = Command::new("cargo")
        .args(["locate-project", "--workspace", "--message-format=plain"])
        .output()
        .context("Failed to locate workspace")?;

    let path = String::from_utf8(output.stdout)
        .context("Invalid UTF-8 in path")?
        .trim()
        .to_string();

    Ok(PathBuf::from(path)
        .parent()
        .context("No parent directory")?
        .to_path_buf())
}
