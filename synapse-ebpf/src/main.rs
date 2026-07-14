//! Synapse eBPF Programs - Kernel-Space Identity Attestation
//!
//! This module contains the eBPF programs that implement Environmental Entanglement.
//! These programs run in kernel space and provide:
//!
//! 1. **task_alloc LSM Hook**: Verify cgroup membership when processes fork
//! 2. **cgroup_skb Filter**: Drop network traffic from untrusted PIDs
//! 3. **tcp_connect kProbe**: Attest connection initiators
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                        Kernel Space                              │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                  │
//! │  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────┐│
//! │  │ task_alloc   │   │ cgroup_skb   │   │   tcp_connect        ││
//! │  │ (LSM Hook)   │   │ (TC Filter)  │   │   (kProbe)           ││
//! │  │              │   │              │   │                      ││
//! │  │ Verify cgroup│   │ Drop packets │   │ Log connection       ││
//! │  │ → Tag PID    │   │ from untrust │   │ attestation events   ││
//! │  └──────┬───────┘   └──────┬───────┘   └──────────┬───────────┘│
//! │         │                  │                      │            │
//! │         └──────────────────┼──────────────────────┘            │
//! │                            │                                    │
//! │                   ┌────────┴────────┐                          │
//! │                   │  TRUSTED_PIDS   │                          │
//! │                   │  (BPF HashMap)  │                          │
//! │                   └─────────────────┘                          │
//! │                                                                  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Safety
//!
//! eBPF programs are verified by the kernel before loading. The verifier ensures:
//! - No unbounded loops (prevents kernel hangs)
//! - No invalid memory access (prevents kernel crashes)
//! - No stack overflow (limited to 512 bytes)
//!
//! Despite this, we use `unsafe` for raw pointer operations required by eBPF.
//!
//! # Known limitations (not fixed in this pass)
//!
//! This file cannot be built or tested without a Linux kernel, so the
//! following known gaps are documented rather than silently left in place:
//! (a) the `task_alloc` LSM hook reads the *calling* (parent) task's PID via
//! `bpf_get_current_pid_tgid()` instead of the newly-allocated child task's
//! PID, so trust does not actually propagate across fork/clone as intended;
//! (b) the `ALLOWED_HASHES` binary-hash map is populated but never consulted
//! by any BPF program in this file; (c) all four hooks fail open (allow) on
//! internal error.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{cgroup_skb, kprobe, lsm, map, xdp},
    maps::{HashMap, PerfEventArray},
    programs::{LsmContext, ProbeContext, SkBuffContext, XdpContext},
};
use aya_log_ebpf::info;

// =============================================================================
// BPF Maps - Shared State Between Programs
// =============================================================================

/// Map of trusted PIDs verified by the task_alloc LSM hook.
/// Key: PID (u32), Value: Trust level (u8, 0=untrusted, 1=trusted)
#[map]
static TRUSTED_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(10240, 0);

/// Ring buffer for sending attestation events to user space.
/// Events include: process creation, network access attempts, violations
#[map]
static ATTESTATION_EVENTS: PerfEventArray<AttestationEvent> = PerfEventArray::new(0);

/// Allowlist of binary hashes (SHA-256 truncated to 64 bits for map key efficiency)
/// Key: Hash prefix (u64), Value: Policy flags (u8)
#[map]
static ALLOWED_HASHES: HashMap<u64, u8> = HashMap::with_max_entries(1024, 0);

// =============================================================================
// Shared Types
// =============================================================================

/// Event sent to user space when attestation occurs
#[repr(C)]
pub struct AttestationEvent {
    /// Process ID
    pub pid: u32,
    /// Parent process ID
    pub ppid: u32,
    /// Event type (0=fork, 1=exec, 2=connect, 3=violation)
    pub event_type: u8,
    /// Verdict (0=denied, 1=allowed)
    pub verdict: u8,
    /// Timestamp (ktime_ns)
    pub timestamp_ns: u64,
}

// =============================================================================
// LSM Hook: task_alloc
// =============================================================================
// This hook fires when a new task (process) is allocated via fork().
// We verify that the parent process is trusted and in the correct cgroup.

/// LSM hook for task allocation - verifies process lineage and cgroup membership.
///
/// # Verification Logic
///
/// 1. Get the parent PID from the current task
/// 2. Check if parent is in TRUSTED_PIDS map
/// 3. Read the cgroup path from task_struct -> css_set -> cgroup
/// 4. Compare against the Synapse cgroup prefix
/// 5. If valid, add child PID to TRUSTED_PIDS; otherwise, log violation
#[lsm(hook = "task_alloc")]
pub fn synapse_task_alloc(ctx: LsmContext) -> i32 {
    match try_task_alloc(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // Allow on error to prevent DoS
    }
}

fn try_task_alloc(ctx: &LsmContext) -> Result<i32, i64> {
    // Get current task's PID
    let pid = unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() as u32 };
    let ppid = (unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() } >> 32) as u32;

    // Check if parent is trusted
    let parent_trusted = unsafe { TRUSTED_PIDS.get(&ppid).copied().unwrap_or(0) };

    if parent_trusted == 1 {
        // Parent is trusted - inherit trust to child
        // Note: In production, we'd also verify cgroup path here
        let _ = TRUSTED_PIDS.insert(&pid, &1, 0);

        info!(ctx, "task_alloc: PID {} inherited trust from PPID {}", pid, ppid);
        return Ok(0); // LSM_RET_SUCCESS
    }

    // Parent not trusted - check cgroup membership
    // This is where we'd traverse task_struct -> css_set -> cgroup -> kernfs_node -> name
    // For now, we log the untrusted fork and allow it (fail-open during development)

    let event = AttestationEvent {
        pid,
        ppid,
        event_type: 0, // fork
        verdict: 0,    // not automatically trusted
        timestamp_ns: unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() },
    };

    // Send event to user space for logging/audit
    // User space can decide to add this PID to trusted list after verification
    unsafe {
        ATTESTATION_EVENTS.output(ctx, &event, 0);
    }

    info!(ctx, "task_alloc: PID {} (PPID {}) requires attestation", pid, ppid);

    Ok(0) // Allow the fork, but don't trust the PID yet
}

// =============================================================================
// cgroup/skb: Network Traffic Filter
// =============================================================================
// This program attaches to the cgroup and filters egress traffic.
// Only trusted PIDs (verified by task_alloc) can send network packets.

/// cgroup_skb program for egress traffic filtering.
///
/// # Enforcement Logic
///
/// 1. Extract the socket's owner PID from sk_buff
/// 2. Look up PID in TRUSTED_PIDS map
/// 3. If trusted (value == 1): Allow packet (return 1)
/// 4. If untrusted: Drop packet (return 0)
#[cgroup_skb]
pub fn synapse_cgroup_egress(ctx: SkBuffContext) -> i32 {
    match try_cgroup_egress(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1, // Allow on error to prevent network DoS
    }
}

fn try_cgroup_egress(ctx: &SkBuffContext) -> Result<i32, i64> {
    // Get the PID of the socket owner
    let pid = unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() as u32 };

    // Check if this PID is trusted
    let trusted = unsafe { TRUSTED_PIDS.get(&pid).copied().unwrap_or(0) };

    if trusted == 1 {
        // Trusted process - allow the packet
        return Ok(1);
    }

    // Untrusted process - drop the packet
    info!(ctx, "cgroup_skb: Dropped packet from untrusted PID {}", pid);

    // Log the violation
    let event = AttestationEvent {
        pid,
        ppid: 0,
        event_type: 3, // violation
        verdict: 0,    // denied
        timestamp_ns: unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() },
    };

    unsafe {
        ATTESTATION_EVENTS.output(ctx, &event, 0);
    }

    Ok(0) // Drop the packet
}

// =============================================================================
// kProbe: tcp_connect
// =============================================================================
// This kprobe attaches to tcp_connect to log connection attempts.
// Used for observability and to trigger WASM policy evaluation.

/// kprobe for tcp_connect - logs connection attempts for attestation.
#[kprobe]
pub fn synapse_tcp_connect(ctx: ProbeContext) -> u32 {
    match try_tcp_connect(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_tcp_connect(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid = unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() as u32 };

    // Log connection attempt
    info!(ctx, "tcp_connect: PID {} initiating connection", pid);

    // Send event to user space for WASM policy evaluation
    let event = AttestationEvent {
        pid,
        ppid: 0,
        event_type: 2, // connect
        verdict: 1,    // pending (user space decides)
        timestamp_ns: unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() },
    };

    unsafe {
        ATTESTATION_EVENTS.output(ctx, &event, 0);
    }

    Ok(0)
}

// =============================================================================
// XDP: Packet Counter (Observability)
// =============================================================================
// Simple XDP program for packet counting. Demonstrates XDP integration.

/// XDP program that counts packets by protocol.
/// This is primarily for observability - actual filtering is done by cgroup_skb.
#[xdp]
pub fn synapse_xdp_counter(ctx: XdpContext) -> u32 {
    match try_xdp_counter(&ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_xdp_counter(_ctx: &XdpContext) -> Result<u32, i64> {
    // In a full implementation, we'd parse the packet headers and count by protocol
    // For now, just pass all packets through
    Ok(xdp_action::XDP_PASS)
}

// =============================================================================
// Panic Handler (Required for #![no_std])
// =============================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
